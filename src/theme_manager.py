import tkinter as tk
from tkinter import ttk
import json
import os


class ThemeManager:
    """Manage dark/light theme switching"""

    DARK_THEME = {
        'name': 'dark',
        'bg': '#0f172a',  # Dark blue background
        'fg': '#e5e7eb',  # Light text
        'panel': '#1e293b',  # Panel background
        'accent': '#3b82f6',  # Blue accent
        'success': '#10b981',  # Green
        'warning': '#f59e0b',  # Yellow
        'danger': '#ef4444',  # Red
        'border': '#475569',  # Border
        'input_bg': '#334155',  # Input background
        'input_fg': '#f1f5f9',  # Input text
        'hover': '#1e40af',  # Hover color
        'disabled': '#64748b',  # Disabled
        'plot_bg': '#1e293b',  # Plot background
        'plot_grid': '#334155',  # Plot grid
        'plot_text': '#e5e7eb',  # Plot text
    }

    LIGHT_THEME = {
        'name': 'light',
        'bg': '#f8fafc',  # Light background
        'fg': '#1e293b',  # Dark text
        'panel': '#ffffff',  # White panel
        'accent': '#2563eb',  # Blue accent
        'success': '#059669',  # Green
        'warning': '#d97706',  # Yellow
        'danger': '#dc2626',  # Red
        'border': '#e2e8f0',  # Border
        'input_bg': '#ffffff',  # Input background
        'input_fg': '#1e293b',  # Input text
        'hover': '#1d4ed8',  # Hover color
        'disabled': '#94a3b8',  # Disabled
        'plot_bg': '#ffffff',  # Plot background
        'plot_grid': '#e2e8f0',  # Plot grid
        'plot_text': '#1e293b',  # Plot text
    }

    def __init__(self, root):
        self.root = root
        self.current_theme = self.DARK_THEME
        self.load_settings()

    def load_settings(self):
        """Load theme preference from file"""
        settings_file = 'theme_settings.json'
        if os.path.exists(settings_file):
            try:
                with open(settings_file, 'r') as f:
                    settings = json.load(f)
                    if settings.get('theme') == 'light':
                        self.current_theme = self.LIGHT_THEME
            except:
                pass

    def save_settings(self):
        """Save theme preference to file"""
        settings_file = 'theme_settings.json'
        with open(settings_file, 'w') as f:
            json.dump({'theme': self.current_theme['name']}, f)

    def switch_theme(self):
        """Toggle between dark and light themes"""
        if self.current_theme['name'] == 'dark':
            self.current_theme = self.LIGHT_THEME
        else:
            self.current_theme = self.DARK_THEME

        self.save_settings()
        return self.current_theme

    def apply_theme(self, widget_dict):
        """Apply theme to all widgets"""
        theme = self.current_theme

        # Apply to root window
        self.root.configure(bg=theme['bg'])

        # Apply to all widgets in dictionary
        for widget_type, widgets in widget_dict.items():
            for widget in widgets:
                try:
                    if widget_type == 'frame':
                        widget.configure(bg=theme['panel'])
                    elif widget_type == 'label':
                        widget.configure(bg=theme['panel'], fg=theme['fg'])
                    elif widget_type == 'button':
                        widget.configure(bg=theme['accent'], fg='white')
                    elif widget_type == 'entry':
                        widget.configure(bg=theme['input_bg'], fg=theme['input_fg'],
                                         insertbackground=theme['fg'])
                    elif widget_type == 'text':
                        widget.configure(bg=theme['input_bg'], fg=theme['input_fg'])
                    elif widget_type == 'canvas':
                        widget.configure(bg=theme['panel'])
                except:
                    pass

        # Configure ttk styles
        self.configure_styles()

    def configure_styles(self):
        """Configure ttk styles for theme"""
        style = ttk.Style()
        theme = self.current_theme

        # Frame styles
        style.configure('TFrame', background=theme['bg'])
        style.configure('Panel.TFrame', background=theme['panel'])

        # Label styles
        style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
        style.configure('Title.TLabel',
                        background=theme['bg'],
                        foreground=theme['fg'],
                        font=('Segoe UI', 16, 'bold'))

        # Button styles
        style.configure('Accent.TButton',
                        background=theme['accent'],
                        foreground='white',
                        borderwidth=0,
                        focuscolor='none')
        style.map('Accent.TButton',
                  background=[('active', theme['hover'])])

        style.configure('Secondary.TButton',
                        background=theme['success'],
                        foreground='white')

        # Entry styles
        style.configure('TEntry',
                        fieldbackground=theme['input_bg'],
                        foreground=theme['input_fg'],
                        insertcolor=theme['fg'])

        # Combobox styles
        style.configure('TCombobox',
                        fieldbackground=theme['input_bg'],
                        foreground=theme['input_fg'],
                        background=theme['panel'])

        # Notebook styles
        style.configure('TNotebook',
                        background=theme['bg'],
                        tabmargins=[2, 5, 2, 0])
        style.configure('TNotebook.Tab',
                        background=theme['panel'],
                        foreground=theme['fg'],
                        padding=[10, 5])
        style.map('TNotebook.Tab',
                  background=[('selected', theme['accent'])],
                  foreground=[('selected', 'white')])

    def get_plot_style(self):
        """Return matplotlib style for current theme"""
        theme = self.current_theme

        plot_style = {
            'figure.facecolor': theme['plot_bg'],
            'axes.facecolor': theme['plot_bg'],
            'axes.edgecolor': theme['border'],
            'axes.labelcolor': theme['plot_text'],
            'axes.titlecolor': theme['plot_text'],
            'xtick.color': theme['plot_text'],
            'ytick.color': theme['plot_text'],
            'grid.color': theme['plot_grid'],
            'text.color': theme['plot_text'],
            'legend.facecolor': theme['panel'],
            'legend.edgecolor': theme['border'],
        }

        return plot_style

    def create_theme_switch_button(self, parent):
        """Create theme toggle button"""
        theme_btn = ttk.Button(parent,
                               text=f"🌙 Dark" if self.current_theme['name'] == 'light' else "☀️ Light",
                               command=lambda: self.update_theme_button(theme_btn),
                               style='Secondary.TButton',
                               width=10)
        theme_btn.pack(side='right', padx=5)
        return theme_btn

    def update_theme_button(self, button):
        """Update theme button text and switch theme"""
        self.switch_theme()
        button.configure(text="🌙 Dark" if self.current_theme['name'] == 'light' else "☀️ Light")