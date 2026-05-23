import re

def main():
    with open('reference_repo/app.py', 'r', encoding='utf-8') as f:
        ref_app = f.read()
        
    with open('app.py', 'r', encoding='utf-8') as f:
        app = f.read()

    # 1. Extract CSS block from reference_repo
    # It starts with render_html("""\n<style>
    # and ends with """)\n\n# ── Main Content Area ──
    css_pattern = re.compile(r'(render_html\("""\n<style>.*?</style>\n"""\))', re.DOTALL)
    ref_css_match = css_pattern.search(ref_app)
    if not ref_css_match:
        print("Could not find CSS block in reference_repo/app.py")
        return
    ref_css = ref_css_match.group(1)

    # Replace CSS block in app.py
    app = css_pattern.sub(ref_css.replace('\\', '\\\\'), app, count=1)
    
    # 2. Extract sidebar_html from reference_repo
    sidebar_pattern = re.compile(r'(sidebar_html = f"""\n<div class="sidebar-container">.*?</div>\n""")', re.DOTALL)
    ref_sidebar_match = sidebar_pattern.search(ref_app)
    if not ref_sidebar_match:
        print("Could not find sidebar_html in reference_repo/app.py")
        return
    ref_sidebar = ref_sidebar_match.group(1)
    
    # Add Authentication to the extracted sidebar
    auth_link = """    <!-- PROFILE Section -->
    <div class="sidebar-section-title">PROFILE</div>
    <a href="{get_nav_link('Authentication')}" target="_self" class="sidebar-nav-item {'active' if current_page == 'Authentication' else ''}">
        <span class="nav-icon">🔑</span> Identity Center
    </a>
"""
    ref_sidebar = ref_sidebar.replace('</div>\n"""', auth_link + '</div>\n"""')

    # Replace sidebar_html in app.py
    app = sidebar_pattern.sub(ref_sidebar.replace('\\', '\\\\'), app, count=1)
    
    # 3. Extract the "Drop your contract" landing page from reference_repo
    landing_pattern = re.compile(r'(if not st\.session_state\[\'analysis_complete\'\]:\n\s+render_html\("""\n\s+<div.*?</div>\n\s+"""\))', re.DOTALL)
    ref_landing_match = landing_pattern.search(ref_app)
    if not ref_landing_match:
        print("Could not find landing page block in reference_repo/app.py")
        return
    ref_landing = ref_landing_match.group(1)
    
    # Replace landing page in app.py
    # Since app.py might have a modified version, let's use a broader regex for app.py
    app_landing_pattern = re.compile(r'(if not st\.session_state\[\'analysis_complete\'\]:\n\s+render_html\("""\n\s+<div.*?</div>\n\s+"""\))', re.DOTALL)
    app = app_landing_pattern.sub(ref_landing.replace('\\', '\\\\'), app, count=1)
    
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(app)
        
    print("Frontend merge complete.")

if __name__ == "__main__":
    main()
