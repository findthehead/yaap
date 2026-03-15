from typing import TypedDict, List, Dict, Any, Optional
from pydantic import BaseModel


class Queries(BaseModel):
    queries: List[str]


class AgentState(TypedDict):
    task: str
    scout: str
    researcher: str
    hunter: str
    reporter: str
    tools : List
    pentest: bool
    content: List[str]
    auth: Optional[bool]  # Whether to attempt authentication (--auth flag)
    tools_runs: List
    findings: List[str]
    report_path: str
    
    # Iterative testing agent states
    checklist: Optional[str]
    checklist_state: Optional[Dict[str, Any]]
    checklist_directive: Optional[Dict[str, Any]]
    discovered_inputs: Optional[List[Dict[str, Any]]]
    current_test_url: Optional[str]
    feroxbuster_endpoints: Optional[List[Dict[str, Any]]]
    endpoint_discovery_success: Optional[bool]
    endpoint_discovery_tool: Optional[str]
    endpoint_discovery_error: Optional[str]
    
    injector: Optional[str]
    injection_plan: Optional[Dict[str, Any]]
    injection_result: Optional[str]
    current_payload_round: Optional[int]
    
    observer: Optional[str]
    observation: Optional[Dict[str, Any]]
    reflection_context: Optional[Dict[str, Any]]  # Reflection analysis from observer
    
    modifier: Optional[str]
    modifier_suggestions: Optional[List[Dict[str, Any]]]
    modification_analysis: Optional[str]
    
    # Encoder agent states (NEW)
    encoder: Optional[str]
    encoded_payload: Optional[str]
    encoding_technique: Optional[str]
    encoding_result: Optional[Dict[str, Any]]
    encoding_history: Optional[List[Dict[str, Any]]]
    encoder_attempts: Optional[int]
    encoding_complete: Optional[bool]
    
    # Validator agent states (NEW)
    validator: Optional[str]
    validation_result: Optional[Dict[str, Any]]
    input_classification: Optional[str]
    routing_decision: Optional[str]
    
    # Login injector agent states (NEW)
    login_injector: Optional[str]
    auth_success: Optional[bool]
    auth_method: Optional[str]
    session_data: Optional[Dict[str, Any]]
    authenticated: Optional[bool]
    
    # Bruteforce agent states (NEW)
    bruteforce: Optional[str]
    bruteforce_success: Optional[bool]
    bruteforce_target: Optional[Dict[str, Any]]
    credentials_found: Optional[Dict[str, Any]]


