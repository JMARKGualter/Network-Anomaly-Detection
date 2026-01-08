import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import pandas as pd
import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import json
import os
import sys

# Set matplotlib to use TkAgg backend explicitly
import matplotlib

matplotlib.use('TkAgg')

# Import project modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from data_loader import load_and_validate_csv
from enhanced_model import EnhancedAnomalyDetector
from visualizations import (
    create_time_series_plot,
    create_distribution_plot,
    create_anomaly_scatter,
    create_protocol_analysis,
    create_heatmap,
    create_arp_analysis
)

# Import the theme manager
try:
    from theme_manager import ThemeManager

    THEME_MANAGER_AVAILABLE = True
except ImportError:
    THEME_MANAGER_AVAILABLE = False

# Import enhanced report generator
try:
    from report_generator import ReportGenerator

    REPORT_GEN_AVAILABLE = True
except ImportError:
    REPORT_GEN_AVAILABLE = False


class NetworkAnomalyDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Anomaly Detection System")
        self.root.geometry("1400x900")

        # Application state
        self.data = None
        self.anomaly_results = None
        self.current_view = "overview"
        self.current_theme = "dark"  # Default theme

        # Initialize theme manager if available
        if THEME_MANAGER_AVAILABLE:
            self.theme_manager = ThemeManager(self.root)
            self.current_theme = self.theme_manager.current_theme['name']

        # Initialize UI
        self.setup_styles()
        self.create_main_layout()

        # Set initial theme
        self.apply_theme()

    def setup_styles(self):
        """Configure ttk styles based on theme"""
        style = ttk.Style()
        style.theme_use('clam')

        # Configure colors based on theme
        if self.current_theme == "dark":
            self.bg_color = "#0f172a"
            self.panel_color = "#1e293b"
            self.accent_color = "#3b82f6"
            self.warning_color = "#ef4444"
            self.success_color = "#10b981"
            self.text_color = "#e5e7eb"
            self.border_color = "#475569"
        else:  # light theme
            self.bg_color = "#f8fafc"
            self.panel_color = "#ffffff"
            self.accent_color = "#2563eb"
            self.warning_color = "#dc2626"
            self.success_color = "#059669"
            self.text_color = "#1e293b"
            self.border_color = "#e2e8f0"

        # Configure root window
        self.root.configure(bg=self.bg_color)

        # Configure styles
        style.configure('Title.TLabel',
                        background=self.bg_color,
                        foreground=self.text_color,
                        font=('Segoe UI', 16, 'bold'))

        style.configure('Panel.TFrame',
                        background=self.panel_color,
                        relief='solid',
                        borderwidth=1)

        style.configure('Accent.TButton',
                        background=self.accent_color,
                        foreground='white',
                        font=('Segoe UI', 10),
                        borderwidth=0)

        style.map('Accent.TButton',
                  background=[('active', self._lighten_color(self.accent_color, 20))])

        style.configure('Warning.TButton',
                        background=self.warning_color,
                        foreground='white')

        style.configure('Success.TButton',
                        background=self.success_color,
                        foreground='white')

        # Configure entry and combobox
        style.configure('TEntry',
                        fieldbackground=self.panel_color if self.current_theme == "light" else "#334155",
                        foreground=self.text_color)

        style.configure('TCombobox',
                        fieldbackground=self.panel_color if self.current_theme == "light" else "#334155",
                        foreground=self.text_color)

    def _lighten_color(self, color, percent):
        """Lighten a color by percent"""
        # Convert hex to RGB
        color = color.lstrip('#')
        rgb = tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))

        # Lighten
        light_rgb = tuple(min(255, int(c * (1 + percent / 100))) for c in rgb)

        # Convert back to hex
        return '#{:02x}{:02x}{:02x}'.format(*light_rgb)

    def create_main_layout(self):
        """Create the main dashboard layout"""

        # Header
        header_frame = ttk.Frame(self.root, style='Panel.TFrame')
        header_frame.pack(fill='x', padx=20, pady=10)

        ttk.Label(header_frame,
                  text="🔍 Network Anomaly Detection System",
                  style='Title.TLabel').pack(side='left', padx=10)

        # Theme toggle button
        if THEME_MANAGER_AVAILABLE:
            theme_text = "☀️ Light" if self.current_theme == "dark" else "🌙 Dark"
            self.theme_btn = ttk.Button(header_frame,
                                        text=theme_text,
                                        command=self.toggle_theme,
                                        style='Success.TButton',
                                        width=10)
            self.theme_btn.pack(side='right', padx=(0, 10))

        # Status label
        self.status_label = ttk.Label(header_frame,
                                      text="Ready to analyze network data",
                                      foreground=self.text_color)
        self.status_label.pack(side='right', padx=10)

        # Main container (sidebar + content)
        main_container = ttk.Frame(self.root)
        main_container.pack(fill='both', expand=True, padx=20, pady=10)

        # Left sidebar
        self.create_sidebar(main_container)

        # Right content area
        self.content_frame = ttk.Frame(main_container, style='Panel.TFrame')
        self.content_frame.pack(side='right', fill='both', expand=True, padx=(10, 0))

        # Initial empty state
        self.show_welcome_screen()

    def toggle_theme(self):
        """Toggle between dark and light themes"""
        if THEME_MANAGER_AVAILABLE:
            self.theme_manager.switch_theme()
            self.current_theme = self.theme_manager.current_theme['name']
            self.setup_styles()
            self.apply_theme()

            # Update theme button text
            theme_text = "☀️ Light" if self.current_theme == "dark" else "🌙 Dark"
            self.theme_btn.configure(text=theme_text)

            # Re-apply theme to all widgets
            if hasattr(self, 'widget_dict'):
                self.theme_manager.apply_theme(self.widget_dict)

            # Refresh current view
            if self.current_view:
                self.switch_view(self.current_view)

    def apply_theme(self):
        """Apply theme colors to root window"""
        self.root.configure(bg=self.bg_color)

    def create_sidebar(self, parent):
        """Create the sidebar with navigation"""
        sidebar = ttk.Frame(parent, width=280, style='Panel.TFrame')
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)

        # Store widgets for theme management
        self.widget_dict = {
            'frame': [sidebar],
            'label': [],
            'button': [],
            'entry': [],
            'text': [],
            'canvas': []
        }

        # Upload section
        upload_frame = ttk.Frame(sidebar)
        upload_frame.pack(fill='x', padx=15, pady=15)
        self.widget_dict['frame'].append(upload_frame)

        upload_label = ttk.Label(upload_frame,
                                 text="📁 DATA SOURCE",
                                 font=('Segoe UI', 10, 'bold'),
                                 foreground=self.accent_color)
        upload_label.pack(anchor='w')
        self.widget_dict['label'].append(upload_label)

        self.upload_btn = ttk.Button(upload_frame,
                                     text="Upload CSV/PCAP",
                                     command=self.upload_data,
                                     style='Accent.TButton')
        self.upload_btn.pack(fill='x', pady=5)
        self.widget_dict['button'].append(self.upload_btn)

        self.data_info_label = ttk.Label(upload_frame,
                                         text="No data loaded",
                                         font=('Segoe UI', 9),
                                         foreground=self._lighten_color(self.text_color, -30))
        self.data_info_label.pack(anchor='w')
        self.widget_dict['label'].append(self.data_info_label)

        # Separator
        ttk.Separator(sidebar, orient='horizontal').pack(fill='x', padx=15, pady=10)

        # Analysis sections
        analysis_frame = ttk.Frame(sidebar)
        analysis_frame.pack(fill='x', padx=15, pady=5)
        self.widget_dict['frame'].append(analysis_frame)

        analysis_label = ttk.Label(analysis_frame,
                                   text="📊 ANALYSIS VIEWS",
                                   font=('Segoe UI', 10, 'bold'),
                                   foreground=self.accent_color)
        analysis_label.pack(anchor='w')
        self.widget_dict['label'].append(analysis_label)

        # View buttons
        views = [
            ("📈 Overview", "overview"),
            ("⏰ Time Series", "time_series"),
            ("📊 Distributions", "distributions"),
            ("🎯 Anomaly Detection", "anomaly_detection"),
            ("🔢 Protocols", "protocols"),
            ("🌐 ARP Analysis", "arp"),
            ("🔥 Heatmap", "heatmap"),
            ("📋 Details", "detailed")
        ]

        self.view_buttons = {}
        for text, view_key in views:
            btn = ttk.Button(analysis_frame,
                             text=text,
                             command=lambda v=view_key: self.switch_view(v),
                             style='TButton')
            btn.pack(fill='x', pady=2)
            btn.state(['disabled'])
            self.view_buttons[view_key] = btn
            self.widget_dict['button'].append(btn)

        # Separator
        ttk.Separator(sidebar, orient='horizontal').pack(fill='x', padx=15, pady=10)

        # Actions section
        actions_frame = ttk.Frame(sidebar)
        actions_frame.pack(fill='x', padx=15, pady=5)
        self.widget_dict['frame'].append(actions_frame)

        actions_label = ttk.Label(actions_frame,
                                  text="⚡ ACTIONS",
                                  font=('Segoe UI', 10, 'bold'),
                                  foreground=self.accent_color)
        actions_label.pack(anchor='w')
        self.widget_dict['label'].append(actions_label)

        # Action buttons
        self.detect_btn = ttk.Button(actions_frame,
                                     text="🚨 Detect Anomalies",
                                     command=self.run_anomaly_detection,
                                     style='Warning.TButton')
        self.detect_btn.pack(fill='x', pady=2)
        self.detect_btn.state(['disabled'])
        self.widget_dict['button'].append(self.detect_btn)

        self.export_btn = ttk.Button(actions_frame,
                                     text="📄 Generate Report",
                                     command=self.export_report)
        self.export_btn.pack(fill='x', pady=2)
        self.export_btn.state(['disabled'])
        self.widget_dict['button'].append(self.export_btn)

        # Model selection
        model_frame = ttk.Frame(actions_frame)
        model_frame.pack(fill='x', pady=(10, 0))
        self.widget_dict['frame'].append(model_frame)

        model_label = ttk.Label(model_frame,
                                text="🤖 Detection Model:",
                                font=('Segoe UI', 9))
        model_label.pack(anchor='w')
        self.widget_dict['label'].append(model_label)

        self.model_var = tk.StringVar(value="Isolation Forest")
        model_combo = ttk.Combobox(model_frame,
                                   textvariable=self.model_var,
                                   values=["Isolation Forest",
                                           "Local Outlier Factor",
                                           "One-Class SVM",
                                           "Autoencoder",
                                           "Ensemble Voting"],
                                   state="readonly",
                                   width=20)
        model_combo.pack(fill='x', pady=2)
        self.widget_dict['entry'].append(model_combo)

    def show_welcome_screen(self):
        """Show initial welcome/upload screen"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        welcome_frame = ttk.Frame(self.content_frame)
        welcome_frame.pack(expand=True, fill='both', padx=50, pady=50)
        self.widget_dict['frame'].append(welcome_frame)

        # Welcome text
        title_label = ttk.Label(welcome_frame,
                                text="Network Anomaly Detection System",
                                font=('Segoe UI', 28, 'bold'),
                                foreground=self.accent_color)
        title_label.pack(pady=20)
        self.widget_dict['label'].append(title_label)

        subtitle_label = ttk.Label(welcome_frame,
                                   text="AI-Powered Network Security & Monitoring",
                                   font=('Segoe UI', 14),
                                   foreground=self._lighten_color(self.text_color, -20))
        subtitle_label.pack(pady=5)
        self.widget_dict['label'].append(subtitle_label)

        # Upload card
        upload_card = ttk.Frame(welcome_frame, style='Panel.TFrame')
        upload_card.pack(pady=30, ipadx=30, ipady=20)
        self.widget_dict['frame'].append(upload_card)

        ttk.Label(upload_card,
                  text="📁",
                  font=('Segoe UI', 64),
                  foreground=self.accent_color).pack(pady=10)

        upload_title = ttk.Label(upload_card,
                                 text="Upload Network Data",
                                 font=('Segoe UI', 18, 'bold'))
        upload_title.pack()
        self.widget_dict['label'].append(upload_title)

        upload_desc = ttk.Label(upload_card,
                                text="Supports: CSV, PCAP files\nDrag & drop or click to browse",
                                font=('Segoe UI', 11),
                                foreground=self._lighten_color(self.text_color, -20))
        upload_desc.pack(pady=10)
        self.widget_dict['label'].append(upload_desc)

        upload_inner_btn = ttk.Button(upload_card,
                                      text="Browse Files",
                                      command=self.upload_data,
                                      style='Accent.TButton')
        upload_inner_btn.pack(pady=15, ipadx=20, ipady=8)
        self.widget_dict['button'].append(upload_inner_btn)

        # Features grid
        features_frame = ttk.Frame(welcome_frame)
        features_frame.pack(pady=30)
        self.widget_dict['frame'].append(features_frame)

        features = [
            ("🤖", "Machine Learning", "5+ anomaly detection algorithms"),
            ("📊", "Visual Analytics", "Multiple visualization views"),
            ("🌗", "Dark/Light Mode", "Customizable interface"),
            ("📋", "Smart Reports", "Automated report generation"),
            ("🔒", "Security Focused", "Real-time threat detection"),
            ("⚡", "Fast Processing", "Optimized for large datasets")
        ]

        for icon, title, desc in features:
            feature_card = ttk.Frame(features_frame, style='Panel.TFrame', width=200, height=120)
            feature_card.pack(side='left', padx=10, ipadx=10, ipady=10)
            feature_card.pack_propagate(False)
            self.widget_dict['frame'].append(feature_card)

            ttk.Label(feature_card,
                      text=icon,
                      font=('Segoe UI', 24)).pack(pady=(10, 5))

            ttk.Label(feature_card,
                      text=title,
                      font=('Segoe UI', 11, 'bold')).pack()

            ttk.Label(feature_card,
                      text=desc,
                      font=('Segoe UI', 9),
                      wraplength=180,
                      justify='center').pack(pady=5)

    def upload_data(self):
        """Handle file upload"""
        filetypes = [
            ("CSV files", "*.csv"),
            ("PCAP files", "*.pcap"),
            ("Text files", "*.txt"),
            ("All files", "*.*")
        ]

        filepath = filedialog.askopenfilename(
            title="Select network data file",
            filetypes=filetypes
        )

        if filepath:
            try:
                self.status_label.config(text=f"Loading {os.path.basename(filepath)}...")
                self.root.update()

                # Load data
                self.data = load_and_validate_csv(filepath)

                # Update UI
                self.data_info_label.config(
                    text=f"✓ {len(self.data):,} rows, {len(self.data.columns)} features"
                )

                # Enable analysis buttons
                for btn in self.view_buttons.values():
                    btn.state(['!disabled'])
                self.detect_btn.state(['!disabled'])

                # Show overview
                self.switch_view("overview")
                self.status_label.config(text=f"Loaded: {os.path.basename(filepath)}")

                # Apply theme to new widgets
                if THEME_MANAGER_AVAILABLE:
                    self.theme_manager.apply_theme(self.widget_dict)

            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file:\n{str(e)}")
                self.status_label.config(text="Error loading file")

    def switch_view(self, view_key):
        """Switch between different analysis views"""
        self.current_view = view_key

        # Update button states
        for key, btn in self.view_buttons.items():
            if key == view_key:
                btn.configure(style='Accent.TButton')
            else:
                btn.configure(style='TButton')

        # Clear content area
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        # Add back button for non-overview views
        if view_key != "overview" and view_key != "welcome":
            nav_frame = ttk.Frame(self.content_frame)
            nav_frame.pack(fill='x', padx=20, pady=10)
            self.widget_dict['frame'].append(nav_frame)

            back_btn = ttk.Button(nav_frame,
                                  text="← Back to Overview",
                                  command=lambda: self.switch_view("overview"),
                                  style='TButton')
            back_btn.pack(anchor='w')
            self.widget_dict['button'].append(back_btn)

        # Show appropriate view
        if view_key == "overview":
            self.show_overview()
        elif view_key == "time_series":
            self.show_time_series()
        elif view_key == "distributions":
            self.show_distributions()
        elif view_key == "anomaly_detection":
            self.show_anomaly_detection()
        elif view_key == "protocols":
            self.show_protocol_analysis()
        elif view_key == "arp":
            self.show_arp_analysis()
        elif view_key == "heatmap":
            self.show_heatmap()
        elif view_key == "detailed":
            self.show_detailed_view()

        # Apply theme to new widgets
        if THEME_MANAGER_AVAILABLE:
            self.theme_manager.apply_theme(self.widget_dict)

    def show_overview(self):
        """Show data overview dashboard"""
        if self.data is None:
            return

        # Create notebook for multiple overview tabs
        notebook = ttk.Notebook(self.content_frame)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        self.widget_dict['frame'].append(notebook)

        # Tab 1: Quick Stats
        stats_frame = ttk.Frame(notebook)
        notebook.add(stats_frame, text="📊 Quick Stats")
        self.widget_dict['frame'].append(stats_frame)

        # Calculate statistics
        stats_text = self.get_data_statistics()
        stats_display = scrolledtext.ScrolledText(stats_frame, height=20,
                                                  bg=self.panel_color,
                                                  fg=self.text_color,
                                                  insertbackground=self.text_color)
        stats_display.insert('1.0', stats_text)
        stats_display.configure(state='disabled')
        stats_display.pack(fill='both', expand=True, padx=10, pady=10)
        self.widget_dict['text'].append(stats_display)

        # Tab 2: Data Preview
        preview_frame = ttk.Frame(notebook)
        notebook.add(preview_frame, text="👁️ Data Preview")
        self.widget_dict['frame'].append(preview_frame)

        # Show first few rows
        preview_text = scrolledtext.ScrolledText(preview_frame, height=20,
                                                 bg=self.panel_color,
                                                 fg=self.text_color,
                                                 insertbackground=self.text_color)
        preview_text.insert('1.0', str(self.data.head(20)))
        preview_text.configure(state='disabled')
        preview_text.pack(fill='both', expand=True, padx=10, pady=10)
        self.widget_dict['text'].append(preview_text)

        # Tab 3: Column Info
        columns_frame = ttk.Frame(notebook)
        notebook.add(columns_frame, text="📋 Column Info")
        self.widget_dict['frame'].append(columns_frame)

        columns_text = scrolledtext.ScrolledText(columns_frame, height=20,
                                                 bg=self.panel_color,
                                                 fg=self.text_color,
                                                 insertbackground=self.text_color)
        col_info = "\n".join([f"{col}: {str(dtype)}"
                              for col, dtype in self.data.dtypes.items()])
        columns_text.insert('1.0', col_info)
        columns_text.configure(state='disabled')
        columns_text.pack(fill='both', expand=True, padx=10, pady=10)
        self.widget_dict['text'].append(columns_text)

        # Static visualization
        if len(self.data.columns) >= 2:
            viz_frame = ttk.Frame(self.content_frame)
            viz_frame.pack(fill='both', expand=True, padx=10, pady=10)
            self.widget_dict['frame'].append(viz_frame)

            try:
                # Apply matplotlib theme
                if THEME_MANAGER_AVAILABLE:
                    plot_style = self.theme_manager.get_plot_style()
                    plt.rcParams.update(plot_style)

                fig = Figure(figsize=(10, 4))
                ax = fig.add_subplot(111)

                # Apply theme to figure
                if self.current_theme == "dark":
                    fig.patch.set_facecolor('#1e293b')
                    ax.set_facecolor('#1e293b')
                    ax.spines['bottom'].set_color('#475569')
                    ax.spines['top'].set_color('#475569')
                    ax.spines['right'].set_color('#475569')
                    ax.spines['left'].set_color('#475569')
                    ax.tick_params(colors='#e5e7eb')
                    ax.xaxis.label.set_color('#e5e7eb')
                    ax.yaxis.label.set_color('#e5e7eb')
                    ax.title.set_color('#e5e7eb')
                else:
                    fig.patch.set_facecolor('#ffffff')
                    ax.set_facecolor('#ffffff')

                # Plot first numeric column
                numeric_cols = self.data.select_dtypes(include=[np.number]).columns
                if len(numeric_cols) > 0:
                    self.data[numeric_cols[0]].plot(kind='line', ax=ax,
                                                    color=self.accent_color,
                                                    linewidth=2)
                    ax.set_title(f"Trend: {numeric_cols[0]}", fontsize=12, pad=10)
                    ax.grid(True, alpha=0.3, color=self.border_color)
                    ax.set_xlabel("Index")
                    ax.set_ylabel(numeric_cols[0])

                canvas = FigureCanvasTkAgg(fig, viz_frame)
                canvas.draw()
                canvas.get_tk_widget().pack(fill='both', expand=True)
                self.widget_dict['canvas'].append(canvas)

                # Add toolbar
                toolbar = NavigationToolbar2Tk(canvas, viz_frame)
                toolbar.update()
                self.widget_dict['frame'].append(toolbar)

            except Exception as e:
                print(f"Error creating plot: {e}")

    def get_data_statistics(self):
        """Generate statistics text for overview"""
        stats = []
        stats.append("=" * 50)
        stats.append("📊 DATA OVERVIEW")
        stats.append("=" * 50)
        stats.append(f"📅 Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        stats.append(f"📁 Total Rows: {len(self.data):,}")
        stats.append(f"📊 Total Columns: {len(self.data.columns)}")
        stats.append(f"💾 Memory Usage: {self.data.memory_usage(deep=True).sum() / 1024:.1f} KB")
        stats.append("")

        stats.append("🔤 COLUMN TYPES:")
        stats.append("-" * 30)
        type_counts = self.data.dtypes.value_counts()
        for dtype, count in type_counts.items():
            stats.append(f"  {dtype}: {count} columns")
        stats.append("")

        stats.append("⚠️ MISSING VALUES:")
        stats.append("-" * 30)
        missing = self.data.isnull().sum()
        missing_cols = missing[missing > 0]
        if len(missing_cols) > 0:
            for col, count in missing_cols.items():
                percentage = (count / len(self.data)) * 100
                stats.append(f"  {col}: {count:,} ({percentage:.1f}%)")
        else:
            stats.append("  ✅ No missing values found")
        stats.append("")

        stats.append("📈 NUMERIC STATISTICS:")
        stats.append("-" * 30)
        numeric_cols = self.data.select_dtypes(include=[np.number]).columns
        for col in numeric_cols[:3]:  # Limit to first 3
            stats.append(f"  {col}:")
            stats.append(f"    Mean: {self.data[col].mean():.2f}")
            stats.append(f"    Std: {self.data[col].std():.2f}")
            stats.append(f"    Min: {self.data[col].min():.2f}")
            stats.append(f"    Max: {self.data[col].max():.2f}")
            stats.append("")

        return "\n".join(stats)

    def show_time_series(self):
        """Show time series analysis"""
        if self.data is None:
            return

        viz_frame = ttk.Frame(self.content_frame)
        viz_frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.widget_dict['frame'].append(viz_frame)

        try:
            # Apply matplotlib theme
            if THEME_MANAGER_AVAILABLE:
                plot_style = self.theme_manager.get_plot_style()
                plt.rcParams.update(plot_style)

            # Create static plot
            fig = create_time_series_plot(self.data)

            # Apply theme to figure
            if self.current_theme == "dark":
                fig.patch.set_facecolor('#1e293b')
                for ax in fig.axes:
                    ax.set_facecolor('#1e293b')

            canvas = FigureCanvasTkAgg(fig, viz_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill='both', expand=True)
            self.widget_dict['canvas'].append(canvas)

            # Add toolbar
            toolbar = NavigationToolbar2Tk(canvas, viz_frame)
            toolbar.update()
            self.widget_dict['frame'].append(toolbar)

        except Exception as e:
            error_label = ttk.Label(viz_frame,
                                    text=f"Error creating time series plot:\n{str(e)}",
                                    font=('Segoe UI', 12))
            error_label.pack(pady=50)
            self.widget_dict['label'].append(error_label)

    def show_distributions(self):
        """Show distribution plots"""
        if self.data is None:
            return

        viz_frame = ttk.Frame(self.content_frame)
        viz_frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.widget_dict['frame'].append(viz_frame)

        try:
            fig = create_distribution_plot(self.data)

            # Apply theme to figure
            if self.current_theme == "dark":
                fig.patch.set_facecolor('#1e293b')
                for ax in fig.axes:
                    ax.set_facecolor('#1e293b')

            canvas = FigureCanvasTkAgg(fig, viz_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill='both', expand=True)
            self.widget_dict['canvas'].append(canvas)

            toolbar = NavigationToolbar2Tk(canvas, viz_frame)
            toolbar.update()
            self.widget_dict['frame'].append(toolbar)

        except Exception as e:
            error_label = ttk.Label(viz_frame,
                                    text=f"Error creating distribution plot:\n{str(e)}",
                                    font=('Segoe UI', 12))
            error_label.pack(pady=50)
            self.widget_dict['label'].append(error_label)

    def run_anomaly_detection(self):
        """Run anomaly detection on loaded data"""
        if self.data is None:
            messagebox.showwarning("Warning", "Please upload data first!")
            return

        try:
            self.status_label.config(text="Running anomaly detection...")
            self.root.update()

            # Use enhanced model
            detector = EnhancedAnomalyDetector()
            self.anomaly_results = detector.detect(
                self.data,
                model_type=self.model_var.get()
            )

            # Enable export button
            self.export_btn.state(['!disabled'])

            # Switch to anomaly view
            self.switch_view("anomaly_detection")
            self.status_label.config(text="Anomaly detection completed!")

            # Show results summary
            anomaly_count = (self.anomaly_results.get('anomaly', 0) == 1).sum()
            messagebox.showinfo(
                "Detection Complete",
                f"Found {anomaly_count} anomalies ({anomaly_count / len(self.data) * 100:.1f}%)\n"
                f"Model: {self.model_var.get()}\n\n"
                f"View results in the 'Anomaly Detection' tab!"
            )

        except Exception as e:
            messagebox.showerror("Error", f"Detection failed:\n{str(e)}")
            self.status_label.config(text="Detection failed")

    def show_anomaly_detection(self):
        """Show anomaly detection results"""
        if self.anomaly_results is None:
            # Show instruction
            instruct_label = ttk.Label(self.content_frame,
                                       text="Run anomaly detection first to see results\n\n"
                                            "Click '🚨 Detect Anomalies' in the sidebar",
                                       font=('Segoe UI', 14),
                                       justify='center')
            instruct_label.pack(pady=50)
            self.widget_dict['label'].append(instruct_label)
            return

        # Create notebook for anomaly views
        notebook = ttk.Notebook(self.content_frame)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        self.widget_dict['frame'].append(notebook)

        # Tab 1: Scatter plot
        scatter_frame = ttk.Frame(notebook)
        notebook.add(scatter_frame, text="🎯 Scatter Plot")
        self.widget_dict['frame'].append(scatter_frame)

        # Plot frame
        scatter_plot_frame = ttk.Frame(scatter_frame)
        scatter_plot_frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.widget_dict['frame'].append(scatter_plot_frame)

        try:
            # Create static scatter plot
            fig = create_anomaly_scatter(self.anomaly_results)

            # Apply theme
            if self.current_theme == "dark":
                fig.patch.set_facecolor('#1e293b')
                for ax in fig.axes:
                    ax.set_facecolor('#1e293b')

            canvas = FigureCanvasTkAgg(fig, scatter_plot_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill='both', expand=True)
            self.widget_dict['canvas'].append(canvas)

            # Add toolbar
            toolbar = NavigationToolbar2Tk(canvas, scatter_plot_frame)
            toolbar.update()
            self.widget_dict['frame'].append(toolbar)

        except Exception as e:
            error_label = ttk.Label(scatter_plot_frame,
                                    text=f"Error creating scatter plot:\n{str(e)}",
                                    font=('Segoe UI', 12))
            error_label.pack(pady=50)
            self.widget_dict['label'].append(error_label)

        # Tab 2: Anomaly list
        list_frame = ttk.Frame(notebook)
        notebook.add(list_frame, text="📋 Anomaly List")
        self.widget_dict['frame'].append(list_frame)

        # Get anomalies
        anomalies = self.anomaly_results[self.anomaly_results.get('anomaly', 0) == 1]

        # Create treeview
        tree_frame = ttk.Frame(list_frame)
        tree_frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.widget_dict['frame'].append(tree_frame)

        tree_scroll = ttk.Scrollbar(tree_frame)
        tree_scroll.pack(side='right', fill='y')

        tree = ttk.Treeview(tree_frame,
                            yscrollcommand=tree_scroll.set,
                            selectmode='extended',
                            height=20)
        tree_scroll.config(command=tree.yview)

        # Define columns
        columns = list(anomalies.columns[:8])  # First 8 columns
        tree['columns'] = columns

        # Format columns
        tree.column("#0", width=0, stretch=False)
        for col in columns:
            tree.column(col, anchor='w', width=120)
            tree.heading(col, text=col, anchor='w')

        # Add data
        for idx, row in anomalies.head(100).iterrows():  # Limit to 100 rows
            values = [str(row[col])[:40] for col in columns]
            tree.insert(parent='', index='end', values=values)

        tree.pack(fill='both', expand=True)

        # Add count label
        count_label = ttk.Label(list_frame,
                                text=f"Showing {min(100, len(anomalies))} of {len(anomalies)} anomalies",
                                font=('Segoe UI', 9))
        count_label.pack(side='bottom', pady=5)
        self.widget_dict['label'].append(count_label)

    def show_protocol_analysis(self):
        """Show protocol-specific analysis"""
        if self.data is None:
            return

        viz_frame = ttk.Frame(self.content_frame)
        viz_frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.widget_dict['frame'].append(viz_frame)

        try:
            fig = create_protocol_analysis(self.data)

            # Apply theme
            if self.current_theme == "dark":
                fig.patch.set_facecolor('#1e293b')
                for ax in fig.axes:
                    ax.set_facecolor('#1e293b')

            canvas = FigureCanvasTkAgg(fig, viz_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill='both', expand=True)
            self.widget_dict['canvas'].append(canvas)

            toolbar = NavigationToolbar2Tk(canvas, viz_frame)
            toolbar.update()
            self.widget_dict['frame'].append(toolbar)

        except Exception as e:
            error_label = ttk.Label(viz_frame,
                                    text=f"Error creating protocol analysis:\n{str(e)}",
                                    font=('Segoe UI', 12))
            error_label.pack(pady=50)
            self.widget_dict['label'].append(error_label)

    def show_arp_analysis(self):
        """Show ARP-specific analysis"""
        if self.data is None:
            return

        viz_frame = ttk.Frame(self.content_frame)
        viz_frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.widget_dict['frame'].append(viz_frame)

        try:
            fig = create_arp_analysis(self.data)

            # Apply theme
            if self.current_theme == "dark":
                fig.patch.set_facecolor('#1e293b')
                for ax in fig.axes:
                    ax.set_facecolor('#1e293b')

            canvas = FigureCanvasTkAgg(fig, viz_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill='both', expand=True)
            self.widget_dict['canvas'].append(canvas)

            toolbar = NavigationToolbar2Tk(canvas, viz_frame)
            toolbar.update()
            self.widget_dict['frame'].append(toolbar)

        except Exception as e:
            error_label = ttk.Label(viz_frame,
                                    text=f"ARP analysis requires specific columns\nError: {str(e)}",
                                    font=('Segoe UI', 12))
            error_label.pack(pady=50)
            self.widget_dict['label'].append(error_label)

    def show_heatmap(self):
        """Show correlation heatmap"""
        if self.data is None:
            return

        viz_frame = ttk.Frame(self.content_frame)
        viz_frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.widget_dict['frame'].append(viz_frame)

        try:
            fig = create_heatmap(self.data)

            # Apply theme
            if self.current_theme == "dark":
                fig.patch.set_facecolor('#1e293b')
                for ax in fig.axes:
                    ax.set_facecolor('#1e293b')

            canvas = FigureCanvasTkAgg(fig, viz_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill='both', expand=True)
            self.widget_dict['canvas'].append(canvas)

            toolbar = NavigationToolbar2Tk(canvas, viz_frame)
            toolbar.update()
            self.widget_dict['frame'].append(toolbar)

        except Exception as e:
            error_label = ttk.Label(viz_frame,
                                    text=f"Error creating heatmap:\n{str(e)}",
                                    font=('Segoe UI', 12))
            error_label.pack(pady=50)
            self.widget_dict['label'].append(error_label)

    def show_detailed_view(self):
        """Show detailed data view"""
        if self.data is None:
            return

        # Create searchable/filterable data table
        main_frame = ttk.Frame(self.content_frame)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.widget_dict['frame'].append(main_frame)

        # Data display
        text_widget = scrolledtext.ScrolledText(main_frame, height=30,
                                                bg=self.panel_color,
                                                fg=self.text_color,
                                                insertbackground=self.text_color)
        text_widget.pack(fill='both', expand=True)
        self.widget_dict['text'].append(text_widget)

        # Show all data (truncated if large)
        if len(self.data) > 1000:
            display_data = self.data.head(1000)
            text_widget.insert('1.0',
                               f"Showing first 1000 of {len(self.data):,} rows\n\n")
            text_widget.insert('end', str(display_data))
            text_widget.insert('end',
                               f"\n\n... and {len(self.data) - 1000:,} more rows")
        else:
            text_widget.insert('1.0', str(self.data))

        text_widget.configure(state='disabled')

    def export_report(self):
        """Export analysis report"""
        if self.data is None:
            return

        try:
            if REPORT_GEN_AVAILABLE:
                # Use enhanced report generator
                generator = ReportGenerator()
                report = generator.generate_comprehensive_report(
                    data=self.data,
                    anomaly_results=self.anomaly_results,
                    analysis_type="full"
                )

                # Ask for report type
                report_type = messagebox.askquestion("Report Type",
                                                     "Generate HTML report?\n\n"
                                                     "Yes: HTML format (view in browser)\n"
                                                     "No: Text format (view in any editor)")

                if report_type == 'yes':
                    # Generate HTML report
                    html_report = generator.generate_html_report(report)
                    filename = filedialog.asksaveasfilename(
                        defaultextension=".html",
                        filetypes=[("HTML files", "*.html"),
                                   ("All files", "*.*")]
                    )
                    if filename:
                        with open(filename, 'w', encoding='utf-8') as f:
                            f.write(html_report)
                else:
                    # Generate text report
                    filename = filedialog.asksaveasfilename(
                        defaultextension=".txt",
                        filetypes=[("Text files", "*.txt"),
                                   ("Markdown files", "*.md"),
                                   ("All files", "*.*")]
                    )
                    if filename:
                        generator.export_report(report, filename)
            else:
                # Fallback to simple report
                report = self.generate_simple_report()
                filename = filedialog.asksaveasfilename(
                    defaultextension=".txt",
                    filetypes=[("Text files", "*.txt"),
                               ("All files", "*.*")]
                )
                if filename:
                    with open(filename, 'w') as f:
                        f.write(report)

            if filename:
                messagebox.showinfo(
                    "Success",
                    f"Report saved to:\n{filename}"
                )
                self.status_label.config(text=f"Report exported: {os.path.basename(filename)}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to export report:\n{str(e)}")

    def generate_simple_report(self):
        """Generate a simple report as fallback"""
        report = []
        report.append("=" * 60)
        report.append("NETWORK ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Data Points: {len(self.data):,}")
        report.append(f"Features: {len(self.data.columns)}")
        report.append("")

        if self.anomaly_results is not None:
            anomaly_count = (self.anomaly_results.get('anomaly', 0) == 1).sum()
            report.append(f"Anomalies Detected: {anomaly_count:,}")
            report.append(f"Anomaly Rate: {anomaly_count / len(self.data) * 100:.1f}%")
            report.append(f"Detection Model: {self.model_var.get()}")

        report.append("")
        report.append("Report generated by Network Anomaly Detection System")

        return "\n".join(report)

    def on_closing(self):
        """Handle window closing"""
        self.root.destroy()


def main():
    root = tk.Tk()
    app = NetworkAnomalyDashboard(root)

    # Handle window closing
    root.protocol("WM_DELETE_WINDOW", app.on_closing)

    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')

    root.mainloop()


if __name__ == "__main__":
    main()