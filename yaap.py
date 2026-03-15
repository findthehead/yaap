import argparse
import os
import time
from getpass import getpass


class Orchestrator:
    def __init__(self):
        parser = argparse.ArgumentParser(description="AI powered Pentesting Tool for Scrooge")
        parser.add_argument("-M", "--model", required=True, help="Model name. For remote providers use their native names (e.g., gpt-4o, claude-3-haiku, gemini-1.5-flash). For local use an Ollama model tag.")
        parser.add_argument("-H", "--host", required=True, help="Target Host or URL")
        parser.add_argument("-T", "--test", choices=["recon", "hunt", "all"], default="recon", help="Specify test mode: 'recon' (reconnaissance only), 'hunt' (skip recon, go straight to hunting), 'all' (complete recon + hunt)")
        parser.add_argument("--max-commands", type=int, help="Max commands planner may select (overrides default)")
        parser.add_argument("--dry-run", action="store_true", help="Plan and print commands but do not execute tools")
        parser.add_argument("--default-timeout", type=int, default=90, help="Default timeout (seconds) for tool execution")
        parser.add_argument("--ensure-basics", action="store_true", help="Always run a baseline header probe (curl -I) in hunt mode")
        # removed experimental CLI args for manual path/param/payload; agent now discovers dynamically
        parser.add_argument("-P", "--provider", choices=["ollama", "openai", "anthropic", "gemini"], help="LLM provider: ollama (local), openai, anthropic, or gemini. If omitted, inferred from model name.")
        parser.add_argument("--auto-install", action="store_true", help="Attempt to auto-install missing external tools via apt (adds Kali repo if needed; requires sudo)")
        parser.add_argument("--auth", action="store_true", help="Attempt authentication using credentials from configs/credentials.json. If omitted, skips login.")
        # Report output format flags
        parser.add_argument("--no-report", action="store_true", help="Disable report generation (show results in terminal only)")
        parser.add_argument("--csv_report", action="store_true", help="Generate CSV report for data analytics (requires report generation enabled)")
        args = parser.parse_args()

        self.args = args
        self.model_name = args.model
        self.provider = args.provider or self._infer_provider(args.model)
        self._ensure_api_key_if_needed(self.provider)
        self.model = self._build_model(self.provider, args.model)
        self.host = args.host
        self.test = args.test
        self.max_commands = args.max_commands
        self.dry_run = args.dry_run
        self.default_timeout = args.default_timeout
        self.ensure_basics = args.ensure_basics
        self.auto_install = args.auto_install
        self.auth = args.auth  # Whether to attempt authentication
        # Output format: disabled if --no-report provided
        self.no_report = args.no_report
        self.output_pdf = not args.no_report  # Generate PDF unless --no-report
        self.output_csv = args.csv_report and not args.no_report  # CSV only with --csv_report and not --no-report
        self.output_json = False  # No JSON output
        self.output_html = False  # No HTML output
        # no manual path/param/payload; discovery + planners handle targets
        if str(self.test).lower() == 'hunt' and self.ensure_basics is False:
            # Default to running a baseline header probe in hunt mode
            self.ensure_basics = True

    def _infer_provider(self, model: str) -> str:
        m = (model or "").lower()
        if m.startswith("gpt") or m.startswith("o1") or m.startswith("o3") or "gpt-" in m:
            return "openai"
        if m.startswith("claude"):
            return "anthropic"
        if m.startswith("gemini"):
            return "gemini"
        return "ollama"

    def _ensure_api_key_if_needed(self, provider: str) -> None:
        if provider == "ollama":
            return
        # Try loading from .env if present without hard dependency on python-dotenv
        try:
            from dotenv import load_dotenv  # type: ignore
            try:
                load_dotenv()
            except Exception:
                pass
        except Exception:
            # dotenv not installed; manually load .env file
            try:
                env_file = os.path.join(os.path.dirname(__file__), '.env')
                if os.path.exists(env_file):
                    with open(env_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#') and '=' in line:
                                key, value = line.split('=', 1)
                                key = key.strip()
                                value = value.strip().strip('"').strip("'")
                                if key and not os.getenv(key):
                                    os.environ[key] = value
            except Exception:
                pass

        env_map = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "gemini": "GOOGLE_API_KEY",
        }
        env_key = env_map.get(provider)
        if not env_key:
            return

        api_key = os.getenv(env_key)
        if not api_key:
            # Do not prompt interactively; fail fast with clear instruction
            raise RuntimeError(
                f"{provider.capitalize()} API key missing. Define {env_key} in environment or in .env before running."
            )

    def _build_model(self, provider: str, model_name: str):
        """Construct the chat model with lazy imports so unused providers
        don't raise ImportError. Prefer env vars for API keys to avoid
        constructor signature drift across versions.
        """
        if provider == "ollama":
            try:
                from langchain_ollama import ChatOllama  # type: ignore
            except ImportError as e:
                raise ImportError("Ollama support requires 'langchain-ollama'. Install it: pip install langchain-ollama") from e
            return ChatOllama(model=model_name)

        if provider == "openai":
            try:
                from langchain_openai import ChatOpenAI  # type: ignore
            except ImportError as e:
                raise ImportError("OpenAI support requires 'langchain-openai'. Install it: pip install langchain-openai") from e
            # Rely on OPENAI_API_KEY in env, avoid passing api_key to handle version differences
            return ChatOpenAI(model=model_name)

        if provider == "anthropic":
            try:
                from langchain_anthropic import ChatAnthropic  # type: ignore
            except ImportError as e:
                raise ImportError("Anthropic support requires 'langchain-anthropic'. Install it: pip install langchain-anthropic") from e
            # Prefer env var ANTHROPIC_API_KEY; do not pass api_key to avoid signature mismatch
            return ChatAnthropic(model=model_name)

        if provider == "gemini":
            try:
                from langchain_google_genai import ChatGoogleGenerativeAI  # type: ignore
            except ImportError as e:
                raise ImportError("Gemini support requires 'langchain-google-genai'. Install it: pip install langchain-google-genai") from e
            # Prefer env var GOOGLE_API_KEY
            return ChatGoogleGenerativeAI(model=model_name)

        # Fallback to ollama if something unexpected occurs
        try:
            from langchain_ollama import ChatOllama  # type: ignore
            return ChatOllama(model=model_name)
        except Exception as e:
            raise RuntimeError(f"Unknown provider '{provider}' and Ollama fallback unavailable: {e}")


def main():
    orch = Orchestrator()
    try:
        # Initialize trace file
        from utils.trace import init_trace, finalize_trace
        trace_file = init_trace(orch.host, orch.test)
        print(f"[*] Trace logging to: {trace_file}\n")
        
        start = time.perf_counter()
        from builder import build
        graph = build(orch=orch)
        thread = {"configurable": {"thread_id": "1"}}
        initial = {
            'task': f"Please do a complete security test on {orch.host}",
            'scout': '',
            'researcher': '',
            'hunter': '',
            'reporter': '',
            'pentest': False,
            'content': [],
            'tools_runs': [],
            'findings': [],
            'report_path': '',
            'auth': getattr(orch, 'auth', False),  # Pass --auth flag to state
            # Encoder-related initial state
            'encoder_attempts': 0,
            'encoding_history': [],
            'encoding_complete': False
        }
        from utils.stream import first_sentence, summarize_tool_run
        from utils.markdown import strip_markdown
        # Hint about flow routing
        try:
            mode = str(getattr(orch, 'test', 'recon')).lower()
            if mode == 'hunt':
                print("[flow] routing: arsenal → researcher → checklist → injector → observer → [encoder] → reporter")
            elif mode == 'all':
                print("[flow] routing: scout → researcher → arsenal → researcher2 → checklist → injector → observer → [encoder] → reporter")
            else:
                print("[flow] routing: scout → researcher → reporter")
        except Exception:
            pass
        
        # Increase recursion limit for iterative testing loop
        config = {**thread, "recursion_limit": 100}
        
        for event in graph.stream(initial, config):
            # Pretty, incremental progress display
            if not isinstance(event, dict):
                print(event)
                continue
            for k, v in event.items():
                if k in ("scout", "researcher", "hunter", "reporter"):
                    preview = first_sentence(strip_markdown(str(v)))
                    try:
                        from utils.ansi import CYAN, YELLOW, RESET
                        print(f"{YELLOW}■[{k}]{RESET} update: {CYAN}{preview}{RESET}...", flush=True)
                    except Exception:
                        print(f"■ [{k}] update: {preview}...", flush=True)
                elif k == 'report_path':
                    try:
                        from utils.ansi import GREEN, RESET
                        print(f"[+] {GREEN}Report written to:{RESET} {v}", flush=True)
                    except:
                        print(f"[+] Report written to: {v}", flush=True)
                    finally:
                        print(f"📄 Report written to: {v}", flush=True)
                elif k == 'tools_runs':
                    # Show last run summary
                    try:
                        last = v[-1]
                        try:
                            from utils.ansi import CYAN, GREEN, RED, YELLOW, RESET
                            status = str(last.get('status'))
                            col = GREEN if status == 'ok' else (RED if status == 'error' else YELLOW)
                            narrative = summarize_tool_run(last)
                            print(f"◇ [tool] {CYAN}{last.get('key')}{RESET} → {col}{status}{RESET} in {YELLOW}{last.get('duration')}{RESET}\n   ↳ {narrative}", flush=True)
                        except Exception:
                            print(f"◇ [tool] {last.get('key')} → {last.get('status')} in {last.get('duration')}\n   ↳ {summarize_tool_run(last)}", flush=True)
                    except Exception:
                        pass
                else:
                    # Minimal print for other updates
                    pass
        end = time.perf_counter()
        finalize_trace()
        print(f'Assesment is completed for {orch.host}\nExact time taken {end - start:.2f} seconds')
    except Exception as e:
        print(f"[-] Failed to run agent invoke: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
