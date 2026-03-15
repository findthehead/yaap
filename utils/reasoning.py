"""
LLM Reasoning Display - Show agent's decision-making process in terminal
Makes the AI interaction transparent and human-like with typing effects
"""

from utils.ansi import CYAN, YELLOW, GREEN, MAGENTA, BLUE, GRAY, RESET, BOLD, DIM
import textwrap
import time
import sys


def _type_text(text: str, delay: float = 0.02):
    """Fast print without delay"""
    print(text, flush=True)


def _slow_print(text: str, delay: float = 0.015):
    """Fast print without delay"""
    print(text, flush=True)


class ReasoningDisplay:
    """Display LLM reasoning steps in a structured, readable format"""
    
    def __init__(self, agent_name: str, color: str = CYAN):
        self.agent_name = agent_name
        self.color = color
        self.step_count = 0
    
    def thinking(self, message: str):
        """Show LLM is thinking/reasoning about something"""
        _slow_print(f"\n{self.color}[*] [{self.agent_name}]{RESET} {BOLD}Thinking:{RESET}", 0.01)
        wrapped = textwrap.fill(message, width=80, initial_indent="   ", subsequent_indent="   ")
        for line in wrapped.split('\n'):
            _type_text(f"{DIM}{line}{RESET}", delay=0.008)
    
    def decision(self, message: str):
        """Show LLM made a decision"""
        self.step_count += 1
        _slow_print(f"\n{YELLOW}➤ [{self.agent_name}]{RESET} {BOLD}Decision #{self.step_count}:{RESET}", 0.01)
        wrapped = textwrap.fill(message, width=80, initial_indent="   ", subsequent_indent="   ")
        for line in wrapped.split('\n'):
            _type_text(line, delay=0.008)
    
    def reasoning(self, message: str):
        """Show LLM reasoning process"""
        _type_text(f"{BLUE}  ├─ Reasoning:{RESET} {DIM}{message}{RESET}", delay=0.008)
    
    def observation(self, message: str):
        """Show what LLM observed from tool output"""
        _type_text(f"{MAGENTA}  ├─ Observation:{RESET} {message}", delay=0.008)
    
    def action(self, tool_name: str, params: dict = None):
        """Show LLM decided to take an action"""
        param_str = ""
        if params:
            # Show key parameters only
            key_params = {k: (v[:50] + '...' if isinstance(v, str) and len(v) > 50 else v) 
                         for k, v in list(params.items())[:3]}
            param_str = f" {GRAY}{key_params}{RESET}"
        _slow_print(f"{GREEN}  └─ Action:{RESET} {BOLD}{tool_name}{RESET}{param_str}", 0.01)
    
    def plan(self, steps: list):
        """Show LLM's plan for approaching the task"""
        _slow_print(f"\n{self.color}[#] [{self.agent_name}]{RESET} {BOLD}Plan:{RESET}", 0.01)
        for i, step in enumerate(steps, 1):
            _type_text(f"{CYAN}  {i}.{RESET} {step}", delay=0.008)
    
    def hypothesis(self, message: str):
        """Show LLM's hypothesis about what might be happening"""
        _type_text(f"{YELLOW}  ├─ Hypothesis:{RESET} {DIM}{message}{RESET}", delay=0.008)
    
    def conclusion(self, message: str):
        """Show LLM's conclusion after reasoning"""
        _slow_print(f"\n{GREEN}✓ [{self.agent_name}]{RESET} {BOLD}Conclusion:{RESET}", 0.01)
        wrapped = textwrap.fill(message, width=80, initial_indent="   ", subsequent_indent="   ")
        for line in wrapped.split('\n'):
            _type_text(line, delay=0.008)
    
    def reflection(self, message: str):
        """Show LLM reflecting on results"""
        _type_text(f"{MAGENTA}  └─ Reflection:{RESET} {DIM}{message}{RESET}", delay=0.008)


def show_llm_response(agent_name: str, response, color: str = CYAN):
    """Display the raw LLM response with reasoning extraction"""
    if not response:
        return
    
    content = getattr(response, 'content', str(response))
    if not content or not isinstance(content, str):
        return
    
    # Parse reasoning from response
    lines = content.split('\n')
    display = ReasoningDisplay(agent_name, color)
    
    in_reasoning = False
    in_plan = False
    plan_steps = []
    
    for line in lines:
        line_lower = line.lower().strip()
        
        # Detect reasoning sections
        if any(marker in line_lower for marker in ['thinking:', 'reasoning:', 'analysis:', 'let me']):
            in_reasoning = True
            display.thinking(line.split(':', 1)[-1].strip() if ':' in line else line)
            continue
        
        if any(marker in line_lower for marker in ['plan:', 'approach:', 'strategy:', 'steps:']):
            in_plan = True
            continue
        
        if in_plan:
            # Extract plan steps (numbered or bulleted)
            if line.strip() and (line.strip()[0].isdigit() or line.strip().startswith(('-', '*', '•'))):
                step = line.strip().lstrip('0123456789.-*•').strip()
                if step:
                    plan_steps.append(step)
            elif plan_steps:  # End of plan section
                display.plan(plan_steps)
                plan_steps = []
                in_plan = False
        
        # Detect decisions
        if any(marker in line_lower for marker in ['i will', 'i should', 'next step', 'therefore']):
            display.decision(line.strip())
        
        # Detect observations
        if any(marker in line_lower for marker in ['i observe', 'i notice', 'i see', 'found:', 'detected:']):
            display.observation(line.strip())
        
        # Detect hypotheses
        if any(marker in line_lower for marker in ['possibly', 'might be', 'could be', 'hypothesis:', 'suspect']):
            display.hypothesis(line.strip())
        
        # Detect conclusions
        if any(marker in line_lower for marker in ['conclusion:', 'summary:', 'in conclusion', 'overall']):
            display.conclusion(line.split(':', 1)[-1].strip() if ':' in line else line)
    
    # Show remaining plan if any
    if plan_steps:
        display.plan(plan_steps)


def show_tool_reasoning(agent_name: str, tool_name: str, tool_input: dict, reasoning: str = None):
    """Show why the LLM decided to use a specific tool"""
    display = ReasoningDisplay(agent_name, CYAN)
    
    if reasoning:
        display.reasoning(reasoning)
    
    # Extract key insights from tool parameters
    insights = []
    if 'url' in tool_input:
        insights.append(f"Target: {tool_input['url']}")
    if 'cmd' in tool_input:
        cmd_preview = tool_input['cmd'][:80] + ('...' if len(tool_input['cmd']) > 80 else '')
        insights.append(f"Command: {cmd_preview}")
    if 'query' in tool_input:
        insights.append(f"Query: {tool_input['query']}")
    if 'max_pages' in tool_input:
        insights.append(f"Scope: {tool_input['max_pages']} pages")
    
    if insights:
        for insight in insights:
            print(f"{GRAY}    {insight}{RESET}", flush=True)
    
    display.action(tool_name, tool_input)


def show_intermediate_thinking(agent_name: str, thought: str):
    """Show LLM's intermediate thoughts during multi-step reasoning"""
    print(f"{BLUE}[*] [{agent_name}]{RESET} {thought}", flush=True)


def show_analysis(agent_name: str, subject: str, findings: list):
    """Show LLM's analysis of results"""
    print(f"\n{MAGENTA}[?] [{agent_name}]{RESET} {BOLD}Analyzing: {subject}{RESET}", flush=True)
    for finding in findings[:5]:  # Show top 5
        print(f"{CYAN}  •{RESET} {finding}", flush=True)
    if len(findings) > 5:
        print(f"{GRAY}  ... and {len(findings) - 5} more{RESET}", flush=True)
