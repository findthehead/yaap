"""
Structured logging module for YAAP
Provides consistent logging across all agents and tools
"""

import logging
import json
import sys
from datetime import datetime
from typing import Any, Dict, Optional


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add extra fields if present
        if hasattr(record, "extra_data"):
            log_data.update(record.extra_data)
        
        return json.dumps(log_data)


def setup_logging(name: str, log_level: str = "INFO", 
                  log_file: Optional[str] = None) -> logging.Logger:
    """
    Set up structured logging for a component
    
    Args:
        name: Logger name
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for logging output
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level))
    
    # Console handler (JSON format)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(JSONFormatter())
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(JSONFormatter())
        logger.addHandler(file_handler)
    
    return logger


def log_vulnerability(logger: logging.Logger, vuln_type: str,
                     severity: str, evidence: Dict[str, Any]):
    """
    Log a discovered vulnerability with structured data
    
    Args:
        logger: Logger instance
        vuln_type: Vulnerability type (XSS, SQLi, etc.)
        severity: Severity level (Critical, High, Medium, Low)
        evidence: Dictionary containing vulnerability evidence
    """
    extra_data = {
        "vulnerability_type": vuln_type,
        "severity": severity,
        "evidence": evidence
    }
    
    record = logging.LogRecord(
        name=logger.name,
        level=logging.WARNING,
        pathname="",
        lineno=0,
        msg=f"Vulnerability discovered: {vuln_type} ({severity})",
        args=(),
        exc_info=None
    )
    record.extra_data = extra_data
    
    logger.handle(record)


def log_tool_execution(logger: logging.Logger, tool_name: str,
                      status: str, duration: float, result: Dict[str, Any]):
    """
    Log tool execution with metrics
    
    Args:
        logger: Logger instance
        tool_name: Name of tool executed
        status: Execution status (success, failure, timeout)
        duration: Execution duration in seconds
        result: Tool result dictionary
    """
    extra_data = {
        "tool_name": tool_name,
        "status": status,
        "duration_seconds": duration,
        "result_keys": list(result.keys()) if isinstance(result, dict) else None
    }
    
    record = logging.LogRecord(
        name=logger.name,
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg=f"Tool execution: {tool_name} - {status}",
        args=(),
        exc_info=None
    )
    record.extra_data = extra_data
    
    logger.handle(record)


def log_agent_decision(logger: logging.Logger, agent_name: str,
                      decision: str, reasoning: str):
    """
    Log an agent's decision and reasoning
    
    Args:
        logger: Logger instance
        agent_name: Name of agent making decision
        decision: The decision made
        reasoning: Reasoning for the decision
    """
    extra_data = {
        "agent_name": agent_name,
        "decision": decision,
        "reasoning": reasoning
    }
    
    record = logging.LogRecord(
        name=logger.name,
        level=logging.DEBUG,
        pathname="",
        lineno=0,
        msg=f"Agent decision: {agent_name} -> {decision}",
        args=(),
        exc_info=None
    )
    record.extra_data = extra_data
    
    logger.handle(record)
