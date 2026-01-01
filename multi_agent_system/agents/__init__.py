"""
Import agent modules to register them with AgentRegistry at package import time.
"""

from .reconnaissance_agent import ReconnaissanceAgent  # noqa: F401
from .authentication_agent import AuthenticationAgent  # noqa: F401
from .input_validation_agent import InputValidationAgent  # noqa: F401
from .file_upload_agent import FileUploadAgent  # noqa: F401  # 🆕 Phase 4.1
from .api_testing_agent import APITestingAgent  # noqa: F401  # 🆕 Phase 4.2
from .authorization_agent import AuthorizationAgent  # noqa: F401
from .session_management_agent import SessionManagementAgent  # noqa: F401
from .error_handling_agent import ErrorHandlingAgent  # noqa: F401
from .weak_crypto_agent import WeakCryptographyAgent  # noqa: F401
from .client_side_agent import ClientSideAgent  # noqa: F401
from .business_logic_agent import BusinessLogicAgent  # noqa: F401
from .config_deploy_agent import ConfigDeploymentAgent  # noqa: F401
from .identity_management_agent import IdentityManagementAgent  # noqa: F401
from .report_generation_agent import ReportGenerationAgent  # noqa: F401  # 🆕 Final: OWASP WSTG 4.2 Report

