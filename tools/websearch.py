import os
from langchain.tools import tool

try:
    from langchain_tavily import TavilySearch
except ImportError:
    TavilySearch = None


def _load_env_file():
    """Manually load .env file if dotenv module is not available"""
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        # Manually load .env file
        try:
            env_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
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


def _normalize_results(raw):
    """Normalize Tavily output to a dict with 'results': [ {title,url,content} ]."""
    out = {"results": []}
    if isinstance(raw, dict) and "results" in raw and isinstance(raw["results"], list):
        for r in raw["results"]:
            if isinstance(r, dict):
                out["results"].append({
                    "title": r.get("title", ""),
                    "url": r.get("url", ""),
                    "content": r.get("content", r.get("snippet", "")),
                })
    elif isinstance(raw, list):
        for r in raw:
            if isinstance(r, dict):
                out["results"].append({
                    "title": r.get("title", ""),
                    "url": r.get("url", ""),
                    "content": r.get("content", r.get("snippet", "")),
                })
            else:
                out["results"].append({"title": "", "url": "", "content": str(r)})
    elif isinstance(raw, str):
        out["results"].append({"title": "", "url": "", "content": raw})
    else:
        out["results"].append({"title": "", "url": "", "content": str(raw)})
    return out


@tool()
def research(query: str, result: int = 5):
    """Search the web using Tavily. Always returns {'results': [{title,url,content}]}.

    If Tavily isn't configured/installed, returns a helpful fallback response.
    """
    _load_env_file()
    api_key = os.getenv("TAVILY_API_KEY")
    
    # Check for placeholder/invalid key
    if api_key and ('placeholder' in api_key.lower() or 'add-your' in api_key.lower()):
        api_key = None
    
    if TavilySearch is None:
        # Silently skip web search when Tavily not installed
        return {"results": []}
    
    if not api_key:
        # Silently skip web search when API key not configured
        # Return empty results to avoid cluttering output
        return {"results": []}

    try:
        tav = TavilySearch(api_key=api_key, max_results=result)
        # Try different method names that Tavily might use
        if hasattr(tav, 'invoke'):
            raw = tav.invoke(query)
            return _normalize_results(raw)
        elif hasattr(tav, 'run'):
            raw = tav.run(query)
            return _normalize_results(raw)
        elif hasattr(tav, 'search'):
            raw = tav.search(query)
            return _normalize_results(raw)
        elif hasattr(tav, '_run'):
            raw = tav._run(query)
            return _normalize_results(raw)
        else:
            # Try calling it directly
            try:
                raw = tav(query)
                return _normalize_results(raw)
            except:
                return {"results": [{"title": "Web search method unavailable", "url": "", "content": f"TavilySearch object has no suitable method. Available: {dir(tav)}"}]}
    except Exception as e:
        return {"results": [{"title": "Web search error", "url": "", "content": f"{e}"}]}
