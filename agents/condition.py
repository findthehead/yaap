from langgraph.graph import END


def proceed(state, orch=None):
    """Decide what comes after scout.

    'recon' proceeds to researcher. 'all' proceeds to researcher with pentest=True.
    'hunt' mode skips scout entirely (handled in builder).
    """
    test = getattr(orch, 'test', None)
    if isinstance(test, str):
        t = test.lower()
        if t == 'all':
            state['pentest'] = True
            return 'researcher'
        if t == 'recon':
            return 'researcher'
    return END


def after_research(state, orch=None):
    """Decide what comes after researcher.

    - In 'hunt' or 'all' mode: proceed to 'arsenal' for attack surface discovery.
    - In 'recon' mode: skip tools and go directly to 'reporter'.
    """
    test = getattr(orch, 'test', None)
    if isinstance(test, str):
        t = test.lower()
        if t in ('hunt', 'all'):
            return 'arsenal'
    return 'reporter'

        
