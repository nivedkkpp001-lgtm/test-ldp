from django.conf import settings
import os
import json
import logging
import subprocess
import ipaddress
import secrets
import hashlib
import base64
import re
from urllib.parse import quote
import requests
from django.db import transaction, IntegrityError
from django.shortcuts import render,get_object_or_404
from django.http import FileResponse, HttpResponse, HttpResponseRedirect
from rest_framework import viewsets, status, generics
from rest_framework.decorators import action, api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from datetime import timedelta
from django.utils import timezone
from django.core.cache import cache

from iam.models import *
from iam.serializers import *
from iam.auth import EnrollmentTokenAuthentication, ControllerAuthentication, IsControllerAuthenticated
from iam.renderers import EncryptedJSONRenderer
from iam.utils.action_utils import build_action_payload
from iam.utils.compliance_utils import save_device_compliance
from iam.utils.agent_url_utils import get_swg_download_url, get_controller_download_url
from iam.utils.mqtt_utils import publish_message_for_device


logger = logging.getLogger("django")

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _resolve_microsoft_tenant_id_from_endpoint(tenant_name):
    safe_tenant = quote(tenant_name, safe="")
    metadata_url = f"https://login.microsoftonline.com/{safe_tenant}/.well-known/openid-configuration"
    response = requests.get(metadata_url, timeout=10)
    response.raise_for_status()
    metadata = response.json()

    issuer = metadata.get("issuer", "")
    for pattern in (
        r"https://sts\.windows\.net/([^/]+)/?",
        r"https://login\.microsoftonline\.com/([^/]+)/?",
    ):
        match = re.search(pattern, issuer)
        if match and UUID_RE.match(match.group(1)):
            return match.group(1)
    return ""

# Create your views here.

class PolicyViewSet(viewsets.ModelViewSet):
    queryset = Policy.objects.all()
    serializer_class = PolicySerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

class CertificateViewSet(viewsets.ModelViewSet):
    queryset = Certificate.objects.all()
    serializer_class = CertificateSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def _ensure_cert_dir(self):
        os.makedirs(settings.RELAY_CERT_DIR, exist_ok=True)

    def _ca_paths(self):
        return (
            os.path.join(settings.RELAY_CERT_DIR, 'ca.key'),
            os.path.join(settings.RELAY_CERT_DIR, 'ca.crt'),
        )

    def _get_device_config(self):
        return (
            'pki:\n'
            ' ca: /etc/nebula/ca.crt\n'
            ' cert: /etc/nebula/host.crt\n'
            ' key: /etc/nebula/host.key\n'
            'static_host_map:\n'
            f'  "192.168.100.1": ["{settings.LIGHTHOUSE_IP}"]\n\n'
            'lighthouse:\n'
            '  am_lighthouse: false\n'
            '  interval: 60\n'
            '  hosts:\n'
            "    - '192.168.100.1'\n\n"
            'firewall:\n'
            '  outbound:\n'
            '    - port: any\n'
            '      proto: any\n'
            '      host: any\n\n'
            '  inbound:\n'
            '    - port: any\n'
            '      proto: any\n'
            '      host: any\n'
        )

    @action(detail=False, methods=['post'])
    def create_ca(self, request):
        self._ensure_cert_dir()
        ca_key, ca_crt = self._ca_paths()
        if os.path.exists(ca_key) and os.path.exists(ca_crt):
            return Response({"message": "CA already exists."}, status=status.HTTP_200_OK)

        cmd = [settings.RELAY_CERT_BIN, 'ca', '-name', settings.RELAY_ORG_NAME]
        try:
            subprocess.check_output(cmd, cwd=settings.RELAY_CERT_DIR, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            return Response({"error": e.output.decode('utf-8')}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Persist a record for CA for tracking (no PEMs stored)
        Certificate.objects.get_or_create(name='ZTNA IAM CA', defaults={
            'device_id': None,
            'cert_file': ca_crt,
            'key_file': ca_key,
        })
        return Response({"message": "CA created successfully."}, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['post'])
    def create_for_device(self, request):
        self._ensure_cert_dir()
        device_id = request.data.get('device_id')
        relay_dir = request.data.get('relay_dir')
        groups = request.data.get('groups', [])     # list of groups
        if not relay_dir:
            return Response({"error": "relay_dir is required"}, status=status.HTTP_400_BAD_REQUEST)

        if not device_id:
            return Response({"error": "device_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        ca_key, ca_crt = self._ca_paths()
        if not (os.path.exists(ca_key) and os.path.exists(ca_crt)):
            return Response({"error": "CA not found. Please create a CA first."}, status=status.HTTP_400_BAD_REQUEST)

        # Determine assigned IP (idempotent per device_id)
        assignment = RelayIPAssignment.objects.filter(device_id=device_id).first()
        assigned_ip = assignment.ip if assignment else None
        reserved_new = False
        if not assigned_ip:
            network = ipaddress.ip_network(settings.NEBULA_NETWORK_CIDR)
            for host_ip in network.hosts():
                try:
                    with transaction.atomic():
                        RelayIPAssignment.objects.update_or_create(
                            ip=str(host_ip),
                            device_id=device_id,
                            relay_dir=relay_dir
                        )
                        assigned_ip = str(host_ip)
                        reserved_new = True
                        break
                except IntegrityError:
                    continue
        if not assigned_ip:
            return Response({"error": "No available IPs in the configured Relay network"}, status=status.HTTP_409_CONFLICT)

        relay_ip = f"{assigned_ip}/{ipaddress.ip_network(settings.RELAY_NETWORK_CIDR).prefixlen}"

        # file names per relay conventions
        host_key = os.path.join(settings.RELAY_CERT_DIR, f'{device_id}.key')
        host_crt = os.path.join(settings.RELAY_CERT_DIR, f'{device_id}.crt')

        # sign via relay-cert (idempotent: re-signing overwrites files)
        cmd = [
            settings.RELAY_CERT_BIN, 'sign',
            '-name', device_id,
            '-ip', relay_ip,
            '-ip', relay_ip,
            '-ca-crt', 'ca.crt',
            '-ca-key', 'ca.key',
        ]
        if groups:
            groups_arg = ','.join(groups) if isinstance(groups, list) else str(groups)
            cmd.extend(['-groups', groups_arg])

        try:
            subprocess.check_output(cmd, cwd=settings.RELAY_CERT_DIR, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            # rollback IP assignment only if this request reserved a new one
            if reserved_new:
                RelayIPAssignment.objects.filter(ip=assigned_ip, device_id=device_id).delete()
            return Response({"error": e.output.decode('utf-8')}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        cert, _ = Certificate.objects.update_or_create(
            device_id=device_id,
            defaults={
                'name': f'Device-{device_id}',
                'relay_ip': relay_ip,
                'groups': groups,
                'cert_file': host_crt,
                'key_file': host_key,
            }
        )
        return Response({"message": f"Certificate created for device {device_id}", "relay_ip": relay_ip}, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['get'])
    def download_for_device(self, request):
        device_id = request.query_params.get('device_id')
        if not device_id:
            return Response({"error": "device_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            cert = Certificate.objects.get(device_id=device_id)
        except Certificate.DoesNotExist:
            return Response({"error": "Certificate not found"}, status=status.HTTP_404_NOT_FOUND)

        resp = {
            'device_id': cert.device_id,
            'relay_ip': cert.relay_ip,
            'groups': cert.groups,
            'config_file': self._get_device_config(),
        }
        try:
            with open(cert.cert_file, 'r') as f:
                resp['certificate'] = f.read()
            with open(cert.key_file, 'r') as f:
                resp['private_key'] = f.read()

            # Add ca.crt file
            self._ensure_cert_dir()
            _, ca_crt = self._ca_paths()
            if not os.path.exists(ca_crt):
                return Response({"error": "CA not found"}, status=status.HTTP_404_NOT_FOUND)
            with open(ca_crt, 'r') as f:
                resp['ca_certificate'] = f.read()

        except OSError as e:
            return Response({"error": f"Failed reading cert files: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(resp)

    @action(detail=False, methods=['get'])
    def download_ca(self, request):
        self._ensure_cert_dir()
        _, ca_crt = self._ca_paths()
        if not os.path.exists(ca_crt):
            return Response({"error": "CA not found"}, status=status.HTTP_404_NOT_FOUND)
        try:
            with open(ca_crt, 'r') as f:
                ca_pem = f.read()
        except OSError as e:
            return Response({"error": f"Failed reading CA file: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({"certificate": ca_pem})

class RelayConfigView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        device_id = request.query_params.get('device_id')
        assignment = None
        relay_dir = "/etc/nebula"
        if device_id:
            assignment = RelayIPAssignment.objects.filter(device_id=device_id).first()
        if assignment and assignment.relay_dir:
            relay_dir = assignment.relay_dir

        yaml_config = f'''pki:
    ca: {relay_dir}/ca.crt
    cert: {relay_dir}/host.crt
    key: {relay_dir}/host.key
static_host_map:
    "192.168.100.1": ["54.80.140.225:4242"]
lighthouse:
    am_lighthouse: false
    interval: 60
    hosts:
      - "192.168.100.1"
firewall:
    outbound:
      - port: any
        proto: any
        host: any
    inbound:
      - port: any
        proto: any
        host: any
'''
        return Response(yaml_config, content_type='text/yaml')

class EnrollmentViewSet(viewsets.ViewSet):
    authentication_classes=[EnrollmentTokenAuthentication]
    permission_classes = [AllowAny]

    supported_os = ['windows', 'darwin', 'linux', 'android']
    supported_arch = ['amd64', 'arm64']

    def _get_register_res(self, msg, device):
        controller_url = get_controller_download_url(device)
        
        from iam.utils.crypto_utils import generate_aes_token, encrypt_initial_credentials
        
        # 1. Generate the raw 32-byte key for specific device
        device.generate_secret_key()
        # 2. Encrypt the credentials STRICTLY using the raw_device_key_bytes
        encrypted_creds = encrypt_initial_credentials(
            credentials_dict={ 
                "id": str(device.id),
                "device_api_key": self.generate_device_api_key(device),
                "secret_key": device.secret_key,
                "ui_enabled": True,
                "mqtt_broker": settings.MQTT.get("BROKER_URL"),
                "mqtt_port": settings.MQTT.get("PORT"),
                "mqtt_username": settings.MQTT.get("USERNAME"),
                "mqtt_password": settings.MQTT.get("PASSWORD"),
            },
            device_secret_key_bytes=base64.urlsafe_b64decode(settings.INITIAL_SECRET_KEY)
        )

        # 3. Return the payload to the device
        res = {
            "message": msg,
            "controller_url": controller_url,
            "api_domain": settings.IAM_PORTAL_DOMAIN,
            "temp_auth_key": generate_aes_token(device),
            "creds": encrypted_creds # The device uses the key to read this
        } 

        return res

    def generate_device_api_key(self, device):
        raw_token = secrets.token_hex(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        key, created = DeviceAPIKey.objects.get_or_create(
            device=device,
            revoked=False,
            defaults={
                "token": raw_token,
                "token_hash": token_hash,
            },
        )

        return key.token if not created else raw_token

    def _get_file_response(self, filename):
        file_path = "change required"

        if not os.path.exists(file_path):
            return HttpResponse("Binary file not found.", status=status.HTTP_404_NOT_FOUND)

        try:
            response = FileResponse(open(file_path, 'rb'), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
        except Exception as e:
            return HttpResponse(f"An error occurred while serving the file: {e}", status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=["post"], authentication_classes=[])
    def validate(self, request):
        """
        Validates the AES-GCM handoff token and cross-checks the
        """
        # 1. Extract the token from the header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return Response(
                {"error": "Missing or improperly formatted Authorization header. Use 'Bearer <token>'."}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        header_token = auth_header.split(" ")[1]

        from iam.utils.crypto_utils import verify_device_handoff
        # 2. Run the hardware handoff verification
        is_valid, message = verify_device_handoff(header_token)

        if not is_valid:
            return Response(
                {"error": message}, 
                status=status.HTTP_403_FORBIDDEN
            )

        # 3. Success! Return the device's secret key to the main binary
        return Response(
            {
                "status": "success", 
                "message": "Device handoff verified successfully.",
                "initial_secret_key": settings.INITIAL_SECRET_KEY
            }, 
            status=status.HTTP_200_OK
        )
    
    @action(detail=False, methods=["post"])
    def register(self, request):

        logger.info(request.data)
        product_uuid = request.data.get("product_uuid")
        if not product_uuid:
            return Response(
                {"error": "product_uuid is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            device = Device.objects.get(product_uuid=product_uuid, is_active=True)
            # Update existing
            serializer = DeviceRegisterSerializer(device, data=request.data, partial=True)
            if serializer.is_valid():
                device = serializer.save()

                # Re-apply effective policies (device + user + group)
                from iam.utils.policy_resolution import get_effective_policies_for_device
                effective = get_effective_policies_for_device(device)
                if effective and not device.disenrollment_key:
                    action = DeviceAction.objects.create(
                        device=device,
                        action_type=DeviceAction.ActionType.POLICY,
                        status=DeviceAction.Status.PENDING,
                    )
                    for entry in effective:
                        action.policies.add(entry["policy"])
                    publish_message_for_device(device, {"policy": True})

                return Response(
                    self._get_register_res(
                        "Device updated successfully",
                        device,
                    ),
                    status=status.HTTP_200_OK,
                )
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Device.DoesNotExist:
            # Create new
            logger.info(request.data)
            serializer = DeviceRegisterSerializer(data=request.data)
            if serializer.is_valid():
                device = serializer.save()

                res = self._get_register_res(
                        "Device registered successfully",
                        device,
                    )

                return Response(
                    res,
                    status=status.HTTP_201_CREATED,
                )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def _queue_base_policy_if_needed(self, device):
        """
        Queue an apply_base_policy action for a device that is unauthenticated
        and doesn't already have a pending base policy action.
        """
        if device.auth_status != Device.AuthStatus.UNAUTHENTICATED:
            return

        has_pending = DeviceAction.objects.filter(
            device=device,
            action_type=DeviceAction.ActionType.STATIC,
            static_action__key=DeviceStaticAction.Key.APPLY_BASE_POLICY,
            status__in=[DeviceAction.Status.PENDING, DeviceAction.Status.SENT],
        ).exists()

        if has_pending:
            return

        try:
            static_action = DeviceStaticAction.objects.get(
                key=DeviceStaticAction.Key.APPLY_BASE_POLICY
            )
        except DeviceStaticAction.DoesNotExist:
            logger.warning(
                '[register] apply_base_policy static action not found in DB — '
                'run: python manage.py load_static_actions'
            )
            return

        DeviceAction.objects.create(
            device=device,
            action_type=DeviceAction.ActionType.STATIC,
            static_action=static_action,
            status=DeviceAction.Status.PENDING,
        )
        logger.info('[register] Queued apply_base_policy for device %s', device.id)

    # @action(detail=False, methods=["get"])
    # def download_controller(self, request):
    #     os_name = request.query_params.get("os")
    #     arch = request.query_params.get("arch")

    #     if not os_name or not arch:
    #         return HttpResponse("Missing 'os' or 'arch' parameters.", status=status.HTTP_400_BAD_REQUEST)

    #     if os_name.lower() not in self.supported_os:
    #         return HttpResponse(f"{os_name} OS not supported", status=status.HTTP_400_BAD_REQUEST)
    #     if arch.lower() not in self.supported_arch:
    #         return HttpResponse(f"{arch} architecture not supported", status=status.HTTP_400_BAD_REQUEST)

    #     filename = f"ztna-controller-{os_name.lower()}-{arch.lower()}"
    #     if os_name.lower() == "windows":
    #         filename = f"{filename}.exe"

    #     download_url = f"{settings.ZTNA_BUCKET_URL}/{filename}"

    #     return HttpResponseRedirect(download_url)

    @action(
        detail=False,
        methods=["get"],
        url_path=r"(?P<os_name>[^/]+)/(?P<arch>[^/]+)",
        authentication_classes=[],
        permission_classes=[AllowAny],
    )
    def enroll(self, request, os_name=None, arch=None):
        if not os_name or not arch:
            return HttpResponse("Missing 'os' or 'arch' parameters.", status=status.HTTP_400_BAD_REQUEST)

        if os_name.lower() not in self.supported_os:
            return HttpResponse(f"{os_name} OS not supported", status=status.HTTP_400_BAD_REQUEST)
        if arch.lower() not in self.supported_arch:
            return HttpResponse(f"{arch} architecture not supported", status=status.HTTP_400_BAD_REQUEST)

        from iam.utils.agent_url_utils import get_installer_download_url
        download_url = get_installer_download_url(os_name, arch)

        return HttpResponseRedirect(download_url)
    
class ControllerConfigViewSet(viewsets.ViewSet):
    authentication_classes = []
    permission_classes = []

    @action(detail=False, methods=['get'])
    def get_binaries(self):   
        return Response({
            "swg_agent": f"{settings.ZTNA_BUCKET_URL}/swg_agent",
            "relay_agent": f"{settings.ZTNA_BUCKET_URL}/relay_agent",
            "ztna_config_files": f"{settings.ZTNA_BUCKET_URL}/ztna_config_files",
            "swg_config_file": f"{settings.ZTNA_BUCKET_URL}/swg_config_file",
            "version": "1.0.0"
        }, status=status.HTTP_200_OK)

class DeviceActionProviderViewSet(viewsets.ViewSet):
    authentication_classes = [ControllerAuthentication]
    renderer_classes = [EncryptedJSONRenderer]
    permission_classes = []

    def _get_next_pending_action(self, device_id):
        """Helper to fetch and lock next pending action for a device."""
        action = (
            DeviceAction.objects
            .select_for_update(skip_locked=True)
            .filter(device=device_id, status=DeviceAction.Status.PENDING)
            .order_by("created_at")
            .first()
        )

        if not action:
            return None

        action.status = DeviceAction.Status.SENT
        action.updated_at = timezone.now()
        action.save(update_fields=["status", "updated_at"])

        if action.action_type in (
            DeviceAction.ActionType.POLICY,
            DeviceAction.ActionType.POLICY_REMOVE,
        ):
            DevicePolicyAssignment.objects.filter(
                device=action.device,
                is_active=True,
                policy__in=action.policies.all(),
            ).update(status=DevicePolicyAssignment.Status.SENT)

        return action

    def _sync_policy_assignments(self, action, has_failure, error_data):
        """
        Propagate the action result back to DevicePolicyAssignment rows so
        the UI endpoint (devices/<id>/policies/) reflects the actual device state.
        """
        if action.action_type not in (
            DeviceAction.ActionType.POLICY,
            DeviceAction.ActionType.POLICY_REMOVE,
        ):
            return

        policies = action.policies.all()
        if not policies.exists():
            return

        if has_failure:
            DevicePolicyAssignment.objects.filter(
                device=action.device,
                is_active=True,
                policy__in=policies,
            ).update(
                status=DevicePolicyAssignment.Status.FAILED,
                last_error=str(error_data),
            )
        else:
            for policy in policies:
                DevicePolicyAssignment.objects.filter(
                    device=action.device,
                    is_active=True,
                    policy=policy,
                ).update(
                    status=DevicePolicyAssignment.Status.APPLIED,
                    applied_version=policy.version,
                    last_error="",
                )

    @transaction.atomic
    def provide(self, request, device_id):
        action = self._get_next_pending_action(device_id)
        device = Device.objects.get(id=device_id)

        # Update last sync time
        device.last_sync_time = timezone.now()
        device.save(update_fields=["last_sync_time"])

        if not action:
            return Response({}, status=status.HTTP_200_OK)

        payload_data = build_action_payload(action, request)

        # Attach payload to action temporarily for serialization
        action.payload = payload_data

        serializer = DeviceActionProviderSerializer(action)
        response_data = serializer.data
        return Response(response_data, status=status.HTTP_200_OK)

    def _ensure_base_policy(self, device):
        """
        If the device is unauthenticated and no base-policy action has ever
        been applied (or is pending), create one now and return it.
        Returns None if the device doesn't need a base policy.
        """
        if device.auth_status != Device.AuthStatus.UNAUTHENTICATED:
            return None

        already_handled = DeviceAction.objects.filter(
            device=device,
            action_type=DeviceAction.ActionType.STATIC,
            static_action__key=DeviceStaticAction.Key.APPLY_BASE_POLICY,
            status__in=[
                DeviceAction.Status.PENDING,
                DeviceAction.Status.SENT,
                DeviceAction.Status.APPLIED,
            ],
        ).exists()

        if already_handled:
            return None

        try:
            static_action = DeviceStaticAction.objects.get(
                key=DeviceStaticAction.Key.APPLY_BASE_POLICY,
            )
        except DeviceStaticAction.DoesNotExist:
            return None

        action = DeviceAction.objects.create(
            device=device,
            action_type=DeviceAction.ActionType.STATIC,
            static_action=static_action,
            status=DeviceAction.Status.SENT,
        )
        logger.info('[provide] Auto-queued apply_base_policy for unauthenticated device %s', device.id)
        return action
        
    @transaction.atomic
    def acknowledge(self, request, action_id):
        """
        POST /acknowledge/<action_id>/

        Payload:
        {
            "acknowledgement": {
                "relay_groups": {"success": false, "error": "..."},
                ...
            }
        }

        Marks the action as APPLIED or FAILED, then returns next pending action (if any).
        """
        try:
            action = DeviceAction.objects.get(pk=action_id)
        except DeviceAction.DoesNotExist:
            return Response(
                {"detail": "Action not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        acknowledgement_data = request.data.get("acknowledgement", {})

        if not isinstance(acknowledgement_data, dict):
            return Response(
                {"detail": "Invalid acknowledgement payload."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if action.action_type == action.ActionType.STATIC:
            has_failure = not bool(acknowledgement_data.get("success"))
            if not has_failure:
                device = action.device
                key = action.static_action.key
                
                swg_settings = getattr(device, 'swg_settings', None)

                # 1. Consolidate SWG_ENABLE and SWG_DISABLE logic
                if key in (DeviceStaticAction.Key.SWG_DISABLE, DeviceStaticAction.Key.SWG_ENABLE) and swg_settings:
                    should_be_enabled = (key == DeviceStaticAction.Key.SWG_ENABLE)
                    
                    swg_settings.is_disabled = not should_be_enabled
                    swg_settings.save(update_fields=['is_disabled'])
                    DevicePolicyAssignment.objects.filter(device=device).update(is_active=should_be_enabled)

                # 2. apply_base_policy — SWG is installed but swg_settings
                #    must NOT be marked active (device is unauthenticated).
                elif key == DeviceStaticAction.Key.APPLY_BASE_POLICY:
                    if not swg_settings:
                        SWGSettings.objects.create(device=device)

                # 3. Handle Disenrollment
                elif key == DeviceStaticAction.Key.SASE_DISENROLLMENT:
                    device.is_active = False
                    device.save(update_fields=['is_active'])

                    if swg_settings:
                        swg_settings.is_active = False
                        swg_settings.save(update_fields=['is_active'])

                elif key == DeviceStaticAction.Key.SCAN_DEVICE:
                    save_device_compliance(device, acknowledgement_data)

        else:
            has_failure = any(
                isinstance(value, dict) and value.get("success") is False
                for value in acknowledgement_data.values()
            )
        if has_failure:
            action.status = DeviceAction.Status.FAILED
            action.last_error = acknowledgement_data
        else:
            action.status = DeviceAction.Status.APPLIED
            action.last_error = None

        action.updated_at = timezone.now()
        action.save(update_fields=["status", "last_error", "updated_at"])

        if action.static_action == DeviceStaticAction.Key.SASE_DISENROLLMENT:
            assined_policies = DevicePolicyAssignment.object.filter(device=action.device)
            assined_policies.delete()

            # Marking as disenrollment
            action.device.is_active = False
            action.device.save()

            return Response(
                {
                    "disenrollment_key": action.device.disenrollment_token,
                    "message": f"Device ID: {action.device} has been disenrolled successfully"
                },
                status=status.HTTP_200_OK
            ) 

        self._sync_policy_assignments(action, has_failure, acknowledgement_data)

        # Try to fetch next pending action for same device
        next_action = self._get_next_pending_action(action.device)

        if next_action:
            payload_data = build_action_payload(next_action, request)
            next_action.payload = payload_data
            serializer = DeviceActionProviderSerializer(next_action)
            return Response(
                serializer.data,
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {"detail": f"Action {action_id} marked as {action.status}. No pending actions."},
                status=status.HTTP_200_OK
            )

class SWGConfigProviderViewSet(viewsets.ViewSet):
    authentication_classes = []
    permission_classes = []

    def provide(self, request, device_id):
        swg_binary_url = ""
        try:
            device = Device.objects.get(id=device_id)
            swg_binary_url = get_swg_download_url(device)

        except Exception as e:
            logger.error(f"Config fetch failed. error: {e}")
            Response({
                "success": False,
                "message": f"Config fetch failed. error: {e}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            "binary": swg_binary_url,
            "certs": {
                "ca_cert": settings.SWG_CA_CERT,
                "ca_key": settings.SWG_CA_KEY
            }
        }, status=status.HTTP_200_OK)

class StatisticsViewSet(viewsets.GenericViewSet):
    """
    POST /devices/<device_id>/statistics
    A ViewSet to create/update statistics of a specific device of a specific date.
    """
    authentication_classes = []
    permission_classes = []
    serializer_class = DeviceSatisticsSerializer

    def create(self, request, device_id=None):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Check if device exists
        try:
            device = Device.objects.get(id=device_id)

            # update swg version on device
            swg_version = request.data.get('swg_version')
            controller_version = request.data.get('controller_version')
            if controller_version:
                ControllerSettings.objects.update_or_create(
                    device=device,
                    defaults={"controller_version": controller_version},
                )

            if swg_version:
                SWGSettings.objects.update_or_create(
                    device=device,
                    defaults={"swg_version": swg_version},
                )
            # logger.info(f"Checking agents version for device -> {device.id}")
            # logger.info(request.data)
            # from iam.utils.static_action_utils import check_agents_version
            # check_agents_version(device, controller_version, swg_version)

        except Device.DoesNotExist:
            return Response(
                {"detail": f"Device with ID {device_id} not found."}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if an entry for the date already exists
        try:
            existingEntry = DeviceStatistics.objects.get(
                device=device,
                date=serializer.validated_data['date']
            )
            # Overwrite existing entry
            serializer = self.get_serializer(existingEntry, data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except DeviceStatistics.DoesNotExist:
            # Create new entry
            serializer.save(device=device)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

class NetworkDetailsViewSet(viewsets.GenericViewSet):
    """
    POST /devices/<device_id>/networkdetails
    A ViewSet to create/update network details of a specific device.
    """
    authentication_classes = []
    permission_classes = []
    serializer_class = DeviceNetworkDetailsSerializer

    def create(self, request, device_id=None):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Check if device exists
        try:
            device = Device.objects.get(id=device_id)
        except Device.DoesNotExist:
            return Response(
                {"detail": f"Device with ID {device_id} not found."}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if an entry already exists
        try:
            existingEntry = DeviceNetworkDetails.objects.get(device=device)
            # Overwrite existing entry
            serializer = self.get_serializer(existingEntry, data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except DeviceNetworkDetails.DoesNotExist:
            # Create new entry
            serializer.save(device=device)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            import traceback
            logger.error(traceback.format_exc())
            return Response(
                {"detail": "Failed to save network details."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class DeviceNetworkIncidentCreateViewSet(generics.CreateAPIView):
    """
    POST /devices/<device_id>/networkincidents
    A ViewSet to add new network incidents from the device.
    """
    authentication_classes = []
    permission_classes = []
    queryset = DeviceNetworkIncident.objects.all()
    serializer_class = DeviceNetworkIncidentSerializer

    def create(self, request, *args, **kwargs):
        is_many = isinstance(request.data, list)        # for bulk adding

        serializer = self.get_serializer(data=request.data, many=is_many)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def perform_create(self, serializer):
        device_id = self.kwargs.get('device_id')
        serializer.save(device_id=device_id)

class DeviceTelemetryViewSet(viewsets.ViewSet):
    """
    Unified endpoint for processing categorized SWG agent telemetry.
    Accepts the payload and queues heavy processing via Celery so the agent
    receives 202 quickly (agent HTTP client timeout is 10s).
    """
    authentication_classes = [ControllerAuthentication]
    renderer_classes = [EncryptedJSONRenderer]
    permission_classes = []

    def create(self, request, *args, **kwargs):
        payload = request.data

        swg_version = payload.get("swg_version")
        controller_version = payload.get("controller_version")

        try:
            device_id = kwargs.get("device_id")
            device = Device.objects.get(id=device_id)

            # logger.info(f"Checking agents version for device -> {device.id}")
            # logger.info(request.data)
            # from iam.utils.static_action_utils import check_agents_version
            # check_agents_version(device, controller_version, swg_version)
            if controller_version:
                ControllerSettings.objects.update_or_create(
                    device=device,
                    defaults={"controller_version": controller_version},
                )

            if swg_version:
                SWGSettings.objects.update_or_create(
                    device=device,
                    defaults={"swg_version": swg_version},
                )

        except Device.DoesNotExist:
            return Response(
                {"detail": f"Device with ID {device_id} not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        stats = payload.get("stats", {})
        url_count = len(stats.get("url_filtering_violations") or [])
        file_count = len(stats.get("file_upload_violations") or [])
        dlp_count = len(stats.get("dlp_violations") or [])
        tenant_count = len(stats.get("tenant_restriction_violations") or [])
        total_items = url_count + file_count + dlp_count + tenant_count

        if total_items > 0:
            from iam.tasks import process_device_telemetry_task
            task = process_device_telemetry_task.delay(device_id, stats)
            logger.info(
                f"Queued telemetry processing for device {device_id}: "
                f"{total_items} items (task_id={task.id})"
            )

        return Response({
            "status": "accepted",
            "queued_items": total_items,
            "message": "Telemetry processing queued" if total_items > 0 else "No telemetry items to process",
        }, status=status.HTTP_202_ACCEPTED)


# ---------------------------
# SASE DEVICE AUTHENTICATION
# ---------------------------
class DeviceAuthViewSet(viewsets.ViewSet):
    """
    SASE Device Authentication & Policy Management.

    Flow:
    1. POST /sase/devices/initiate/ — Device sends user email, gets IDP config for that domain
    2. POST /sase/devices/complete-auth/ — Device sends IDP tokens after successful OAuth, gets user mapped + policy
    3. GET  /sase/devices/<id>/policy/ — Fetch current policy for authenticated device
    4. GET  /sase/devices/<id>/status/ — Get device auth status
    5. POST /sase/devices/<id>/logout/ — Log out user from device
    """

    authentication_classes = [ControllerAuthentication]
    renderer_classes = [EncryptedJSONRenderer]
    permission_classes = [IsControllerAuthenticated]

    def _get_authorized_device(self, request, target_id=None):
        """
        Return the authenticated device, enforcing that the target ID (from
        URL pk or request body) matches request.device.  Returns (device, None)
        on success or (None, Response) on authorization failure.
        """
        device = getattr(request, 'device', None)
        if device is None:
            return None, Response(
                {'success': False, 'error': 'Authentication required.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if target_id is not None and int(target_id) != device.id:
            return None, Response(
                {'success': False, 'error': 'You are not authorized to access this device.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        if not device.is_active:
            return None, Response(
                {'success': False, 'error': 'Device not found or not active.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        return device, None

    def initiate(self, request):
        """
        Validate device, return the server-side OAuth sign-in URL.
        The controller opens this URL in a webview; the user picks an IDP
        and the entire OAuth flow (PKCE, redirect, token exchange) happens
        server-side.
        """
        device_id = request.data.get('device_id')
        if not device_id:
            return Response(
                {'success': False, 'error': 'device_id is required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        device, err_resp = self._get_authorized_device(request, target_id=device_id)
        if err_resp:
            return err_resp

        import hmac as _hmac
        iam_domain = settings.IAM_PORTAL_DOMAIN
        nonce = secrets.token_urlsafe(32)
        sig = _hmac.new(
            device.secret_key.encode(),
            f"{device.id}:{nonce}".encode(),
            hashlib.sha256,
        ).hexdigest()
        oauth_url = (
            f"https://{iam_domain}/api/agent/sase/oauth/signin/"
            f"?device_id={device.id}&nonce={nonce}&sig={sig}"
        )

        logger.info('SASE initiate: device=%s', device_id)

        return Response({
            'success': True,
            'device_id': device.id,
            'oauth_url': oauth_url,
        }, status=status.HTTP_200_OK)

    def _resolve_idp_for_domain(self, domain):
        """Match an active IdP config by email domain, or return the first active config."""
        active_configs = IdPConfiguration.objects.filter(is_active=True).order_by('id')
        if not active_configs.exists():
            return None

        domain_lower = (domain or '').lower()
        if domain_lower:
            for idp_config in active_configs:
                extra = idp_config.extra_data or {}
                allowed_domains = extra.get('domains') or []
                if allowed_domains:
                    allowed = {d.lower() for d in allowed_domains if isinstance(d, str)}
                    if domain_lower in allowed:
                        return idp_config

        return active_configs.first()

    def _build_base_policy(self, idp_configs, device=None):
        """
        Build the Base Policy for unauthenticated devices.
        
        This policy BLOCKS all traffic EXCEPT:
        - Controller API endpoints (IAM portal domain)
        - IDP authentication URLs (OAuth sign-in flow)
        
        The output is SWG-compatible (same rules.json structure) so the
        controller can feed it directly to the SWG binary via apply_base_policy.
        """
        allowed_domains = [
            settings.IAM_PORTAL_DOMAIN,
        ]
        
        allowed_domains.extend([
            'login.microsoftonline.com',
            'login.microsoft.com',
            'login.live.com',
            'graph.microsoft.com',
            'aadcdn.msauth.net',
            'aadcdn.msftauth.net',
            'accounts.google.com',
            'oauth2.googleapis.com',
            'www.googleapis.com',
        ])

        for idp in idp_configs:
            if idp.base_url:
                from urllib.parse import urlparse
                parsed = urlparse(idp.base_url)
                if parsed.netloc:
                    allowed_domains.append(parsed.netloc)
        
        allowed_domains = list(set(allowed_domains))

        idp_domains = [d for d in allowed_domains if d != settings.IAM_PORTAL_DOMAIN]

        swg_config = {
            'urlFiltering': {
                'enabled': True,
                'mode': 'whitelist',
                'allowedUrls': allowed_domains,
                'blockedCategories': [],
                'commandUUID': 'base-policy',
                'whitelistHash': '',
            },
            'tenantRestriction': {
                'microsoft': {'enabled': False},
                'google': {'enabled': False},
            },
            'fileUploadRestriction': {
                'enabled': True,
                'blockAll': True,
                'fileType': [],
                'mimeType': [],
                'fileUploadWhitelist': allowed_domains,
            },
            'fileDownloadRestriction': {
                'enabled': True,
                'blockAll': True,
                'fileType': [],
                'mimeType': [],
                'useRoles': False,
            },
            'businessHours': {'enabled': False},
            'dlpConfig': {
                'enabled': False,
                'copyPasteRestriction': False,
                'rules': {},
                'webhook': {'enabled': False},
            },
            'trustedNetwork': {'enabled': False},
            'dynamicTunneling': {'enabled': False},
            'proxyExemptions': {'enabled': False, 'domains': []},
            'interceptorConfig': {
                'enabled': True,
                'controller_domain': settings.IAM_PORTAL_DOMAIN,
                'idp_domains': idp_domains,
                'allowed_domains': allowed_domains,
            },
            "trafficCapture": {
                                "enabled": True,
                                "mode": "windivert",
                                "proxyHost": "127.0.0.1",
                                "proxyPort": 8080,
                                "interceptMode": "all_tcp",
                                "interceptPorts": [80, 443],
                                "passthroughPorts": [],
                                "dropQUIC": True,
                                "dropIPv6": True,
                                "excludeLoopback": True,
                                "customFilter": "",
                                "appendFilter": "",
                                "priority": 0,
                                "queueLength": 4096,
                                "queueTime": 2000,
                                "queueSize": 4194304,
                                "exemptIPs": ["127.0.0.1", "54.82.235.37"],
                                "exemptCIDRs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                                "upstreamBindPortMin": 41000,
                                "upstreamBindPortMax": 41199
                            }
        }

        base_policy = {
            'policy_type': 'base',
            'description': 'Base policy for unauthenticated devices - blocks all traffic except Controller/IDP',
            'enforcement_mode': 'strict',
            'allowed_domains': allowed_domains,
            'config': swg_config,
        }

        if device:
            from iam.utils.agent_url_utils import get_swg_download_url
            base_policy['swg_setup'] = {
                'binary': get_swg_download_url(device),
                'certs': {
                    'ca_cert': settings.SWG_CA_CERT,
                    'ca_key': settings.SWG_CA_KEY,
                },
                'config': swg_config,
            }

        return base_policy

    def _get_user_policy(self, device):
        """
        Get the network policy for an authenticated user/device.
        Uses the policy resolution engine to merge device-direct, user-level,
        and group-level assignments with proper precedence.
        """
        from iam.utils.policy_utils import build_policy_payload
        from iam.utils.policy_resolution import get_effective_policies_for_device
        
        effective_entries = get_effective_policies_for_device(device)
        
        if not effective_entries:
            return {
                'policy_type': 'default',
                'description': 'Default authenticated user policy - no restrictions',
                'enforcement_mode': 'permissive',
                'policies': [],
            }
        
        policies = []
        for entry in effective_entries:
            try:
                policy_data = build_policy_payload(entry["policy"])
                policies.append(policy_data)
            except Exception as e:
                logger.error(f"Failed to build policy {entry['policy'].id}: {e}")
        
        user_label = device.user.email if device.user else 'unknown'
        return {
            'policy_type': 'user',
            'description': f'Policy for user {user_label}',
            'enforcement_mode': 'normal',
            'policies': policies,
        }

    def policy(self, request, pk=None):
        """Return the current policy for a device (base or user-specific)."""
        device, err_resp = self._get_authorized_device(request, target_id=pk)
        if err_resp:
            return err_resp

        device = Device.objects.select_related('user').get(id=device.id)

        if device.auth_status == Device.AuthStatus.UNAUTHENTICATED:
            return Response({
                'success': True,
                'device_id': device.id,
                'auth_status': device.auth_status,
            }, status=status.HTTP_200_OK)

        return Response({
            'success': True,
            'device_id': device.id,
            'auth_status': device.auth_status,
            'user': {
                'id': device.user.id,
                'email': device.user.email,
                'name': device.user.name,
            } if device.user else None,
            'policy': self._get_user_policy(device),
        }, status=status.HTTP_200_OK)

    def status(self, request, pk=None):
        """Return the current authentication status of a device."""
        from iam.serializers import DeviceAuthStatusSerializer

        device, err_resp = self._get_authorized_device(request, target_id=pk)
        if err_resp:
            return err_resp

        device = Device.objects.select_related('user', 'idp_config').get(id=device.id)

        data = DeviceAuthStatusSerializer(device).data
        # TEMP AUTH BYPASS: always report as authenticated
        data['auth_status'] = 'authenticated'
        logger.info(data)

        return Response(data, status=status.HTTP_200_OK)

    def logout(self, request, pk=None):
        """Log out the user from a device and revert to base policy enforcement."""
        device, err_resp = self._get_authorized_device(request, target_id=pk)
        if err_resp:
            return err_resp

        with transaction.atomic():
            device = Device.objects.select_for_update().get(id=device.id)
            previous_user = device.user
            device.user = None
            device.auth_status = Device.AuthStatus.UNAUTHENTICATED
            device.idp_config = None
            device.idp_access_token = None
            device.idp_refresh_token = None
            device.idp_token_expires_at = None
            device.save()

        try:
            publish_message_for_device(device, {'auth_status': 'unauthenticated'})
        except Exception as e:
            logger.warning('Failed to publish MQTT message for device %s: %s', pk, e)

        logger.info(
            'SASE logout: device=%s previous_user=%s',
            pk,
            previous_user.email if previous_user else None,
        )

        return Response({
            'success': True,
            'device_id': device.id,
            'auth_status': device.auth_status,
            'message': 'User logged out. Device reverted to unauthenticated state.',
        }, status=status.HTTP_200_OK)


# ---------------------------------------------------------------------------
# SASE SERVER-SIDE OAUTH VIEWS
# These are plain Django views (not DRF) — rendered in the controller webview.
# ---------------------------------------------------------------------------

from django.views import View
from django.views.decorators.clickjacking import xframe_options_exempt
from django.utils.decorators import method_decorator
from urllib.parse import urlencode, urlparse


@method_decorator(xframe_options_exempt, name='dispatch')
class OAuthSignInView(View):
    """
    IAM-hosted sign-in page rendered inside the controller Wails webview.

    GET /sase/oauth/signin/?device_id=<id>

    Shows SSO provider buttons for each active IdP configuration.
    Clicking a button redirects to /sase/oauth/authorize/?idp_id=<id>&device_id=<id>.
    """

    PROVIDER_META = {
        'AZURE': {'label': 'Microsoft', 'icon': 'microsoft'},
        'GOOGLE': {'label': 'Google', 'icon': 'google'},
        'OKTA': {'label': 'Okta', 'icon': 'okta'},
    }

    def get(self, request):
        import hmac as _hmac
        device_id = request.GET.get('device_id', '')
        nonce = request.GET.get('nonce', '')
        sig = request.GET.get('sig', '')
        error = request.GET.get('error', '')

        if not device_id or not nonce or not sig:
            return render(request, 'sase/oauth_signin.html', {
                'device_id': device_id,
                'error': 'Invalid sign-in link. Please try again from the application.',
                'providers': [],
            })

        try:
            device = Device.objects.get(id=int(device_id), is_active=True)
        except (ValueError, Device.DoesNotExist):
            return render(request, 'sase/oauth_signin.html', {
                'device_id': device_id,
                'error': 'Device not found or not active.',
                'providers': [],
            })

        expected_sig = _hmac.new(
            device.secret_key.encode(),
            f"{device.id}:{nonce}".encode(),
            hashlib.sha256,
        ).hexdigest()
        if not _hmac.compare_digest(sig, expected_sig):
            return render(request, 'sase/oauth_signin.html', {
                'device_id': device_id,
                'error': 'Invalid sign-in link. Please try again from the application.',
                'providers': [],
            })

        active_cfgs = list(IdPConfiguration.objects.filter(is_active=True).order_by('id'))
        provider_counts = {}
        for cfg in active_cfgs:
            provider_counts[cfg.provider] = provider_counts.get(cfg.provider, 0) + 1

        providers = []
        for cfg in active_cfgs:
            meta = self.PROVIDER_META.get(cfg.provider, {'label': cfg.provider, 'icon': 'default'})
            label = meta['label']
            if provider_counts[cfg.provider] > 1:
                label = f"{label} ({cfg.name})"
            
            providers.append({
                'id': cfg.id,
                'name': cfg.name,
                'provider': cfg.provider,
                'label': label,
                'icon': meta['icon'],
            })

        return render(request, 'sase/oauth_signin.html', {
            'device_id': device_id,
            'nonce': nonce,
            'sig': sig,
            'error': error,
            'providers': providers,
        })


class OAuthAuthorizeView(View):
    """
    Entry point for server-side OAuth.

    GET /sase/oauth/authorize/?idp_id=<id>&device_id=<id>

    1. Validates the device exists and looks up the IDP by id
    2. Generates PKCE code_verifier/challenge and a random state
    3. Stores a OAuthSession row
    4. 302-redirects the browser/webview to the IDP authorization URL
    """

    def get(self, request):
        import hmac as _hmac
        idp_id = request.GET.get('idp_id')
        device_id = request.GET.get('device_id')
        nonce = request.GET.get('nonce', '')
        sig = request.GET.get('sig', '')

        if not idp_id or not device_id:
            return render(request, 'sase/oauth_error.html', {
                'error': 'Missing idp_id or device_id parameter.',
            }, status=400)

        if not nonce or not sig:
            return render(request, 'sase/oauth_error.html', {
                'error': 'Invalid sign-in link. Please try again from the application.',
            }, status=400)

        try:
            device_id = int(device_id)
            device = Device.objects.get(id=device_id, is_active=True)
        except (ValueError, Device.DoesNotExist):
            return render(request, 'sase/oauth_error.html', {
                'error': 'Device not found or not active.',
            }, status=404)

        expected_sig = _hmac.new(
            device.secret_key.encode(),
            f"{device.id}:{nonce}".encode(),
            hashlib.sha256,
        ).hexdigest()
        if not _hmac.compare_digest(sig, expected_sig):
            return render(request, 'sase/oauth_error.html', {
                'error': 'Invalid sign-in link. Please try again from the application.',
            }, status=403)

        try:
            idp_config = IdPConfiguration.objects.get(id=int(idp_id), is_active=True)
        except (ValueError, IdPConfiguration.DoesNotExist):
            return render(request, 'sase/oauth_error.html', {
                'error': 'Identity provider not found or not active.',
            }, status=404)

        code_verifier = secrets.token_urlsafe(32)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b'=').decode()

        state = secrets.token_urlsafe(32)

        iam_domain = settings.IAM_PORTAL_DOMAIN
        redirect_uri = f"https://{iam_domain}/api/agent/sase/oauth/callback/"

        OAuthSession.objects.create(
            state=state,
            code_verifier=code_verifier,
            device=device,
            idp_config=idp_config,
            redirect_uri=redirect_uri,
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        auth_url = self._build_auth_url(idp_config, state, code_challenge, redirect_uri)

        logger.info(
            'SASE OAuth authorize: device=%s idp=%s(%s)',
            device_id, idp_config.name, idp_config.id,
        )

        return HttpResponseRedirect(auth_url)

    def _build_auth_url(self, idp_config, state, code_challenge, redirect_uri):
        if idp_config.provider == 'AZURE':
            base = f"https://login.microsoftonline.com/{idp_config.tenant_id}/oauth2/v2.0/authorize"
            params = urlencode({
                'client_id': idp_config.client_id,
                'response_type': 'code',
                'redirect_uri': redirect_uri,
                'response_mode': 'query',
                'scope': 'openid profile email offline_access',
                'state': state,
                'code_challenge': code_challenge,
                'code_challenge_method': 'S256',
                'prompt': 'select_account',
            })
            return f"{base}?{params}"
        raise ValueError(f"Unsupported IDP provider: {idp_config.provider}")


class OAuthCallbackView(View):
    """
    IDP redirects back here after user authenticates.

    GET /sase/oauth/callback/?code=<code>&state=<state>

    1. Looks up the OAuthSession by state
    2. Exchanges the authorization code for tokens (server-to-server)
    3. Validates the id_token via JWKS
    4. Creates/updates DeviceUser, maps to Device, saves policy
    5. Renders success or error HTML (shown in the controller webview)
    """

    def get(self, request):
        code = request.GET.get('code')
        state = request.GET.get('state')
        error_param = request.GET.get('error')
        error_desc = request.GET.get('error_description', '')

        if error_param:
            return render(request, 'sase/oauth_error.html', {
                'error': f'{error_param}: {error_desc}' if error_desc else error_param,
            })

        if not code or not state:
            return render(request, 'sase/oauth_error.html', {
                'error': 'Missing authorization code or state parameter.',
            }, status=400)

        try:
            session = OAuthSession.objects.select_related(
                'device', 'idp_config',
            ).get(state=state, is_consumed=False)
        except OAuthSession.DoesNotExist:
            return render(request, 'sase/oauth_error.html', {
                'error': 'Invalid or expired sign-in session.',
            }, status=400)

        if session.is_expired():
            session.is_consumed = True
            session.save(update_fields=['is_consumed'])
            return render(request, 'sase/oauth_error.html', {
                'error': 'Sign-in session has expired. Please try again.',
            })

        session.is_consumed = True
        session.save(update_fields=['is_consumed'])

        idp_config = session.idp_config

        try:
            tokens = self._exchange_code(idp_config, code, session.code_verifier, session.redirect_uri)
        except Exception as e:
            logger.error('SASE OAuth token exchange failed: %s', e)
            return render(request, 'sase/oauth_error.html', {
                'error': 'Failed to exchange authorization code for tokens.',
            })

        id_token = tokens.get('id_token', '')
        if not id_token:
            return render(request, 'sase/oauth_error.html', {
                'error': 'Identity provider did not return an ID token.',
            })

        try:
            user_info = self._validate_id_token(id_token, idp_config)
        except Exception as e:
            logger.error('ZTNA OAuth token validation failed: %s', e)
            return render(request, 'sase/oauth_error.html', {
                'error': f'Token validation failed: {e}',
            })

        token_email = (user_info.get('email') or '').lower()
        if not token_email:
            return render(request, 'sase/oauth_error.html', {
                'error': 'Identity provider did not return an email address.',
            })

        try:
            self._complete_device_auth(session, tokens, user_info)
        except Exception as e:
            logger.exception('SASE OAuth complete_device_auth failed: %s', e)
            return render(request, 'sase/oauth_error.html', {
                'error': 'Failed to complete device authentication.',
            })

        logger.info(
            'SASE OAuth callback success: device=%s email=%s',
            session.device_id, token_email,
        )

        return render(request, 'sase/oauth_success.html', {
            'email': token_email,
            'name': user_info.get('name', token_email.split('@')[0]),
        })

    # ── helpers ──────────────────────────────────────────────

    def _exchange_code(self, idp_config, code, code_verifier, redirect_uri):
        import requests as http_requests

        if idp_config.provider == 'AZURE':
            token_url = f"https://login.microsoftonline.com/{idp_config.tenant_id}/oauth2/v2.0/token"
            data = {
                'client_id': idp_config.client_id,
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': redirect_uri,
                'code_verifier': code_verifier,
                'scope': 'openid profile email offline_access',
            }

            extra = idp_config.extra_data or {}
            client_secret = extra.get('client_secret')
            if client_secret:
                data['client_secret'] = client_secret

            resp = http_requests.post(token_url, data=data, timeout=30)
            if resp.status_code != 200:
                raise Exception(f"Token endpoint returned {resp.status_code}: {resp.text[:500]}")
            return resp.json()

        raise Exception(f"Unsupported IDP provider: {idp_config.provider}")

    def _validate_id_token(self, token, idp_config):
        from jose import jwt as jose_jwt, JWTError
        import requests as http_requests

        if idp_config.provider == 'AZURE':
            jwks_uri = f"https://login.microsoftonline.com/{idp_config.tenant_id}/discovery/v2.0/keys"
            jwks = http_requests.get(jwks_uri, timeout=10).json()

            try:
                decoded = jose_jwt.decode(
                    token, jwks,
                    algorithms=['RS256'],
                    audience=idp_config.client_id,
                    options={'verify_aud': True},
                )
                return {
                    'email': decoded.get('preferred_username') or decoded.get('email') or decoded.get('upn'),
                    'name': decoded.get('name', ''),
                    'sub': decoded.get('sub'),
                    'oid': decoded.get('oid'),
                }
            except JWTError as e:
                raise Exception(f"Token validation error: {e}")

        raise Exception(f"Unsupported IDP provider: {idp_config.provider}")

    def _get_source_from_provider(self, provider):
        mapping = {
            'AZURE': DeviceUser.SourceTypes.AZURE,
            'OKTA': DeviceUser.SourceTypes.OKTA,
            'GOOGLE': DeviceUser.SourceTypes.GOOGLE,
        }
        return mapping.get(provider, DeviceUser.SourceTypes.MANUAL)

    def _complete_device_auth(self, session, tokens, user_info):
        token_email = (user_info.get('email') or '').lower()
        idp_config = session.idp_config

        with transaction.atomic():
            device = Device.objects.select_for_update().get(id=session.device_id)

            device_user, created = DeviceUser.objects.get_or_create(
                email=token_email,
                defaults={
                    'name': user_info.get('name') or token_email.split('@')[0],
                    'source': self._get_source_from_provider(idp_config.provider),
                    'idp_config': idp_config,
                },
            )
            if not created:
                update_fields = []
                name = user_info.get('name')
                if name and device_user.name != name:
                    device_user.name = name
                    update_fields.append('name')
                if device_user.idp_config_id != idp_config.id:
                    device_user.idp_config = idp_config
                    update_fields.append('idp_config')
                if update_fields:
                    device_user.save(update_fields=update_fields + ['updated_at'])

            device.user = device_user
            device.auth_status = Device.AuthStatus.AUTHENTICATED
            device.idp_config = idp_config
            device.last_auth_time = timezone.now()
            device.idp_access_token = tokens.get('access_token', '')
            device.idp_refresh_token = tokens.get('refresh_token', '')
            expires_in = tokens.get('expires_in') or 3600
            device.idp_token_expires_at = timezone.now() + timedelta(seconds=int(expires_in))
            device.save()

            # Queue policy actions using the resolution engine so the controller
            # transitions from base policy to user's effective policies (device + user + group).
            from iam.utils.policy_resolution import get_effective_policies_for_device
            effective = get_effective_policies_for_device(device)
            if effective:
                policy_action = DeviceAction.objects.create(
                    device=device,
                    action_type=DeviceAction.ActionType.POLICY,
                    status=DeviceAction.Status.PENDING,
                )
                for entry in effective:
                    policy_action.policies.add(entry["policy"])
                logger.info(
                    'SASE OAuth: queued POLICY action for device %s with %d effective policies',
                    device.id, len(effective),
                )

        try:
            publish_message_for_device(device, {'policy': True, 'auth_status': 'authenticated'})
        except Exception as e:
            logger.warning('SASE OAuth: MQTT publish failed for device %s: %s', device.id, e)


class MicrosoftTenantResolveViewSet(viewsets.ViewSet):
    authentication_classes = [ControllerAuthentication]
    permission_classes = [IsControllerAuthenticated]

    def retrieve(self, request, *args, **kwargs):
        tenant_name = (request.query_params.get("domain") or request.query_params.get("tenant") or "").strip().lower()
        if not tenant_name:
            return Response({"detail": "domain is required"}, status=status.HTTP_400_BAD_REQUEST)

        cached = MicrosoftTenantLookup.objects.filter(tenant_name=tenant_name).first()
        if cached:
            return Response({
                "tenant_name": cached.tenant_name,
                "tenant_id": cached.tenant_id,
                "source": "db",
            }, status=status.HTTP_200_OK)

        # Avoid hammering the external Microsoft metadata endpoint by
        inflight_key = f"microsoft_tenant_inflight:{tenant_name}"
        inflight_ttl = 30  # seconds

        # If another worker already started resolving this tenant, return
        if not cache.add(inflight_key, True, inflight_ttl):
            return Response({"detail": "lookup in progress"}, status=status.HTTP_202_ACCEPTED)

        try:
            tenant_id = None
            try:
                tenant_id = _resolve_microsoft_tenant_id_from_endpoint(tenant_name)
            except (requests.RequestException, ValueError) as exc:
                logger.error("Microsoft tenant lookup failed for %s: %s", tenant_name, exc)
                return Response({"detail": "microsoft tenant lookup failed"}, status=status.HTTP_502_BAD_GATEWAY)

            if not tenant_id:
                return Response({"detail": "tenant id not found"}, status=status.HTTP_404_NOT_FOUND)

            lookup, _ = MicrosoftTenantLookup.objects.update_or_create(
                tenant_name=tenant_name,
                defaults={"tenant_id": tenant_id},
            )
            return Response({
                "tenant_name": lookup.tenant_name,
                "tenant_id": lookup.tenant_id,
                "source": "microsoft",
            }, status=status.HTTP_200_OK)
        finally:
            try:
                cache.delete(inflight_key)
            except Exception:
                # If cache backend isn't configured or delete fails, ignore —
                # the inflight marker is best-effort and will expire.
                pass
