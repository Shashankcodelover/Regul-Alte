import re

def main():
    with open('app.py', 'r', encoding='utf-8') as f:
        app = f.read()

    css_addition = """
/* === Responsive Sidebar & Mobile Menu === */
@media screen and (min-width: 769px) {
    [data-testid="stSidebar"] {
        display: block !important;
        min-width: 250px !important;
    }
    .mobile-header {
        display: none !important;
    }
}

@media screen and (max-width: 768px) {
    .mobile-header {
        display: flex;
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 60px;
        background: #0f1115;
        z-index: 999999;
        align-items: center;
        justify-content: space-between;
        padding: 0 15px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.5);
    }
    .mobile-menu-btn {
        color: #ffffff;
        font-size: 1.5rem;
        cursor: pointer;
        padding: 5px;
    }
    /* Hide native Streamlit header */
    header[data-testid="stHeader"] {
        display: none !important;
    }
    .block-container {
        padding-top: 80px !important;
    }
}
"""
    # Append the CSS right before the closing </style> tag
    app = app.replace('</style>', css_addition + '\n</style>', 1)
    
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(app)
        
if __name__ == "__main__":
    main()
