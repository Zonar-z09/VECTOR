"""
web/theme.py — Shared branding + polish layer for the VECTOR dashboard.

Called once near the top of every page (after st.set_page_config). Purely
presentational: injects CSS and renders a consistent branded header. No
business logic lives here — matches the dashboard's "view layer only" rule.
"""

import textwrap

import streamlit as st

# Warm gold as the interactive accent (buttons, checkboxes, active nav, links)
# instead of teal/blue, so the UI isn't monochrome. Slate-blue reserved for
# structural/secondary touches (icon outline) so there's a deliberate second
# tone rather than one color repeated everywhere.
ACCENT = "#c9973f"
SECONDARY = "#4a7185"
VERIFIED_GREEN = "#4caf7d"


def _html(s: str) -> None:
    """Render a multi-line HTML string, stripped of common leading
    whitespace first — Streamlit's markdown renderer otherwise treats
    4+ leading spaces as a fenced code block and prints the raw tags."""
    st.markdown(textwrap.dedent(s).strip(), unsafe_allow_html=True)


def _shield_svg(size: int = 30) -> str:
    """Small inline shield+check mark matching the project's cover art."""
    return f"""
    <svg width="{size}" height="{size}" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
      <polygon points="50,6 88,20 88,54 50,94 12,54 12,20"
               fill="#161d27" stroke="{SECONDARY}" stroke-width="4" stroke-linejoin="round"/>
      <polyline points="32,50 45,64 70,34" fill="none" stroke="{VERIFIED_GREEN}"
                stroke-width="9" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    """.strip()


def inject_css() -> None:
    _html(f"""
    <style>
    /* Streamlit's own fixed top toolbar sits above the content area; push the
       block container down far enough that our header never sits under it
       (the previous smaller value let the toolbar clip the wordmark). */
    .block-container {{ padding-top: 4.5rem; }}
    header[data-testid="stHeader"] {{ background: transparent; }}

    /* Card-style metric tiles */
    div[data-testid="stMetric"] {{
        background: linear-gradient(180deg, rgba(255,255,255,0.035), rgba(255,255,255,0.01));
        border: 1px solid rgba(255,255,255,0.08);
        border-left: 3px solid {ACCENT};
        border-radius: 10px;
        padding: 14px 16px 10px 16px;
    }}
    div[data-testid="stMetricLabel"] {{
        color: #9aa5b8;
        font-size: 0.82rem;
        letter-spacing: 0.02em;
    }}
    div[data-testid="stMetricValue"] {{
        color: #f2f5f9;
    }}

    /* Section dividers a touch quieter than Streamlit's default */
    hr {{ border-color: rgba(255,255,255,0.10) !important; }}

    /* Buttons: pill-shaped, accent-outlined, with a smooth lift on hover
       instead of Streamlit's flat instant-swap default. */
    .stButton > button, .stDownloadButton > button {{
        border-radius: 999px;
        border: 1px solid {ACCENT};
        font-weight: 600;
        padding: 0.5rem 1.4rem;
        transition: transform 0.15s ease, box-shadow 0.15s ease, background-color 0.15s ease, color 0.15s ease;
    }}
    .stButton > button:hover, .stDownloadButton > button:hover {{
        background-color: {ACCENT};
        color: #14181f;
        box-shadow: 0 4px 14px rgba(201, 151, 63, 0.28);
        transform: translateY(-1px);
    }}
    .stButton > button:active, .stDownloadButton > button:active {{
        transform: translateY(0px);
        box-shadow: none;
    }}
    .stButton > button[kind="primary"] {{
        background-color: {ACCENT};
        border-color: {ACCENT};
        color: #14181f;
    }}
    .stButton > button[kind="primary"]:hover {{
        box-shadow: 0 4px 16px rgba(201, 151, 63, 0.4);
        filter: brightness(1.08);
    }}
    .stButton > button:disabled {{
        opacity: 0.4;
        transform: none;
        box-shadow: none;
    }}

    /* Dataframes: subtle rounded frame */
    div[data-testid="stDataFrame"] {{
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 8px;
        overflow: hidden;
    }}

    /* Sidebar: quiet divider, larger and more legible nav labels */
    section[data-testid="stSidebar"] {{
        border-right: 1px solid rgba(255,255,255,0.06);
    }}
    section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"],
    section[data-testid="stSidebar"] nav a {{
        font-size: 1.05rem;
        padding: 0.55rem 0.9rem;
        border-radius: 8px;
    }}
    section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"] span,
    section[data-testid="stSidebar"] nav a span {{
        font-size: 1.05rem;
    }}
    section[data-testid="stSidebar"] [aria-current="page"] {{
        background-color: rgba(201, 151, 63, 0.14);
        border-left: 3px solid {ACCENT};
    }}

    .vector-brand-caption {{
        color: #8b95a8;
        font-size: 0.92rem;
        margin-top: -6px;
    }}
    .vector-brand-rule {{
        height: 2px;
        width: 46px;
        background: {ACCENT};
        border: none;
        margin: 10px 0 18px 0;
        border-radius: 2px;
    }}
    </style>
    """)


def brand_header(page_title: str | None = None, subtitle: str | None = None) -> None:
    """Renders the shield-mark + VECTOR wordmark, optionally with a page title
    and a one-line subtitle, followed by a thin accent rule. Call once per page,
    right after st.set_page_config()."""
    inject_css()

    icon = _shield_svg(30)
    title_html = f'<span style="opacity:0.55; font-weight:400;"> / {page_title}</span>' if page_title else ""
    _html(f"""
    <div style="display:flex; align-items:center; gap:10px; margin-bottom:0;">
        {icon}
        <span style="font-size:1.7rem; font-weight:800; letter-spacing:0.01em; color:#f2f5f9;">
            VECTOR{title_html}
        </span>
    </div>
    """)
    if subtitle:
        _html(f'<div class="vector-brand-caption">{subtitle}</div>')
    _html('<hr class="vector-brand-rule">')
