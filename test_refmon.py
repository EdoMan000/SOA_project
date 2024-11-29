import os
import subprocess
import pandas as pd
import matplotlib.pyplot as plt
from rich.console import Console
import shutil

# Define directories and files
base_dir = "./refmon_test"
results_dir = os.path.join(base_dir, "results")
graphs_dir = os.path.join(base_dir, "graphs")
baseline_executable = "./baseline_test_run"
test_executable = "./refmon_test_run"
baseline_csv = os.path.join(results_dir, "baseline.csv")
test_results_csv = os.path.join(results_dir, "results.csv")
raw_results_file = os.path.join(results_dir, "rawResults.csv")
console = Console()

# Create results directory
os.makedirs(results_dir, exist_ok=True)


def clear_screen():
    """Clear the console screen."""
    os.system("cls" if os.name == "nt" else "clear")


def wait_for_keypress():
    """Wait for user to press any key."""
    console.print("[bold cyan]Press Enter to return to the menu...[/bold cyan]")
    input()
    clear_screen()


def execute_command_ignore_error(command, description):
    """Execute a shell command and ignore errors."""
    console.print(f"[bold green]Running: {description}[/bold green]")
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError:
        # Ignore errors and proceed
        console.print(f"[bold yellow]{description} already in the desired state, continuing...[/bold yellow]")


def execute_test(executable):
    """Execute a test executable with taskset and chrt."""
    try:
        subprocess.run(["taskset", "0x2", "sudo", "chrt", "90", executable], check=True)
    except FileNotFoundError:
        console.print(f"[bold red]Error: {executable} not found. Ensure it is compiled and available.[/bold red]")
        wait_for_keypress()
        return False
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Test execution failed with error: {e}[/bold red]")
        wait_for_keypress()
        return False
    return True


def run_tests():
    """Run the tests, generate graphs, and clean up."""
    # Run make down before baseline tests
    execute_command_ignore_error("sudo make down", "make down")

    console.print("[bold green]Starting baseline tests...[/bold green]")
    raw_data = []

    # Execute baseline test 200 times
    for run in range(1, 201):
        console.print(f"Run {run}/200...")
        if not execute_test(baseline_executable):
            return
        if os.path.exists(baseline_csv):
            baseline_df = pd.read_csv(baseline_csv)
            for _, row in baseline_df.iterrows():
                raw_data.append(["NO_REFMON", row["Threads"], row["Read Time (cycles)"], row["Write Time (cycles)"], row["Create Time (cycles)"]])

    # Save baseline results to rawResults.csv
    raw_df = pd.DataFrame(raw_data, columns=["N", "Threads", "Read Time (cycles)", "Write Time (cycles)", "Create Time (cycles)"])
    raw_df.to_csv(raw_results_file, index=False)
    console.print(f"[bold green]Baseline test results saved to {raw_results_file}[/bold green]")

    # Run make up before RefMon tests
    execute_command_ignore_error("make up", "make up")

    console.print("[bold green]Starting RefMon tests...[/bold green]")
    if os.path.exists(raw_results_file):
        raw_data = pd.read_csv(raw_results_file).values.tolist()

    # Execute RefMon test 200 times
    for run in range(1, 201):
        console.print(f"Run {run}/200...")
        if not execute_test(test_executable):
            return
        if os.path.exists(test_results_csv):
            test_df = pd.read_csv(test_results_csv)
            for _, row in test_df.iterrows():
                raw_data.append([row["N"], row["Threads"], row["Read Time (cycles)"], row["Write Time (cycles)"], row["Create Time (cycles)"]])

    # Save updated results
    raw_df = pd.DataFrame(raw_data, columns=["N", "Threads", "Read Time (cycles)", "Write Time (cycles)", "Create Time (cycles)"])
    raw_df.to_csv(raw_results_file, index=False)
    console.print(f"[bold green]Test results saved to {raw_results_file}[/bold green]")

    # Generate and show boxplots
    generate_boxplots()

def custom_sort_key(value):
    # Try to convert to float to determine if it's a number
    try:
        float(value)
        return (1, float(value))  # Numbers come second, sorted numerically
    except ValueError:
        return (0, value.lower())  # Strings come first, sorted lexicographically


def generate_boxplots():
    """Generate boxplots with Matplotlib using subplots for each thread count."""
    if not os.path.exists(raw_results_file):
        console.print("[bold yellow]Raw results file missing. Perform tests first.[/bold yellow]")
        wait_for_keypress()
        return

    y_limits, show_outliers = get_graph_preferences()

    try:
        raw_df = pd.read_csv(raw_results_file)

        # Ensure graphs directory is clean
        if os.path.exists(graphs_dir):
            shutil.rmtree(graphs_dir)
        os.makedirs(graphs_dir)

        # Ensure 'Threads' is numeric
        raw_df['Threads'] = pd.to_numeric(raw_df['Threads'])

        operations = ["Read Time (cycles)", "Write Time (cycles)", "Create Time (cycles)"]
        thread_counts = sorted(raw_df["Threads"].unique())

        for op in operations:
            # Determine Y-axis limits for the current operation
            if op in y_limits and y_limits[op] != (None, None):
                op_lower_bound_y, op_upper_bound_y = y_limits[op]
            else:
                op_lower_bound_y = raw_df[op].min()
                op_upper_bound_y = raw_df[op].max()

            # Create a figure with subplots for each thread count
            fig, axes = plt.subplots(nrows=1, ncols=len(thread_counts), figsize=(16, 6), sharey=True)

            for ax, thread in zip(axes, thread_counts):
                # Filter data for the current thread count
                df_thread = raw_df[raw_df["Threads"] == thread]

                # Get unique 'N' values in desired order
                unique_n = sorted(df_thread["N"].unique(), key=custom_sort_key)

                # Collect data for each 'N'
                data = []
                labels = []
                for n in unique_n:
                    subset = df_thread[df_thread["N"] == n][op].dropna()
                    if len(subset) > 0:
                        data.append(subset.values)
                        labels.append(n)

                if len(data) == 0:
                    ax.set_visible(False)  # Hide subplot if no data
                    continue

                # Create boxplot
                bplot = ax.boxplot(data, showfliers=show_outliers, patch_artist=True)
                ax.set_title(f"Threads = {int(thread)}")
                ax.set_xlabel('Number of Protected Files')
                ax.set_xticklabels(labels, rotation=45)
                if op_lower_bound_y is not None and op_upper_bound_y is not None:
                    ax.set_ylim(op_lower_bound_y, op_upper_bound_y)
                ax.grid(True)

            # Set common Y-axis label
            axes[0].set_ylabel(op)

            # Set overall title
            plt.suptitle(f'Boxplots of {op} by Number of Protected Files for Each Thread Count')

            plt.tight_layout(rect=[0, 0.03, 1, 0.95])  # Adjust the layout to make room for the suptitle

            # Save the figure
            output_path = os.path.join(graphs_dir, f"{op.replace(' ', '_')}_boxplot.png")
            plt.savefig(output_path)

            console.print(f"[bold green]Boxplot for {op} saved to {output_path}[/bold green]")

            # Display the plot
            #plt.show()
        wait_for_keypress()

    except Exception as e:
        console.print(f"[bold red]Failed to generate boxplots: {e}[/bold red]")
        wait_for_keypress()


def get_graph_preferences():
    """Prompt the user for custom Y-axis limits per operation and outliers or default behavior."""
    operations = ["Read Time (cycles)", "Write Time (cycles)", "Create Time (cycles)"]
    y_limits = {}
    outliers = True

    console.print("[bold yellow]Do you want to specify custom Y-axis limits for the graphs? (y/n)[/bold yellow]")
    choice = console.input("[bold yellow]>>> [/bold yellow]").strip().lower()
    if choice == "y":
        for op in operations:
            console.print(f"[bold yellow]Specify Y-axis limits for {op}:[/bold yellow]")
            try:
                lower_bound = console.input("[bold yellow]Enter the lower bound for Y-axis (or leave blank for default): [/bold yellow]")
                upper_bound = console.input("[bold yellow]Enter the upper bound for Y-axis (or leave blank for default): [/bold yellow]")
                lower_bound = float(lower_bound) if lower_bound.strip() != '' else None
                upper_bound = float(upper_bound) if upper_bound.strip() != '' else None
                y_limits[op] = (lower_bound, upper_bound)
            except ValueError:
                console.print("[bold red]Invalid input! Using default Y-axis limits for this operation.[/bold red]")
                y_limits[op] = (None, None)
    elif choice != "n":
        console.print("[bold red]Invalid input! Using default Y-axis limits.[/bold red]")

    console.print("[bold yellow]Do you want to show outliers in the graphs? (y/n)[/bold yellow]")
    choice = console.input("[bold yellow]>>> [/bold yellow]").strip().lower()
    if choice == "n":
        outliers = False
    elif choice != "y":
        console.print("[bold red]Invalid input! Showing outliers as default.[/bold red]")

    return y_limits, outliers


def main_menu():
    try:
        while True:
            clear_screen()
            console.print("""
[bold yellow]██████╗ ███████╗███████╗███╗   ███╗ ██████╗ ███╗   ██╗     ████████╗███████╗ ██████╗████████╗[/bold yellow]
[bold yellow]██╔══██╗██╔════╝██╔════╝████╗ ████║██╔═══██╗████╗  ██║     ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝[/bold yellow]
[bold yellow]██████╔╝█████╗  █████╗  ██╔████╔██║██║   ██║██╔██╗ ██║        ██║   █████╗  ███████╗   ██║   [/bold yellow]
[bold yellow]██╔══██╗██╔══╝  ██╔══╝  ██║╚██╔╝██║██║   ██║██║╚██╗██║        ██║   ██╔══╝  ╚════██║   ██║   [/bold yellow]
[bold yellow]██║  ██║███████╗██║     ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║        ██║   ███████╗██████╔╝   ██║   [/bold yellow]
[bold yellow]╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝        ╚═╝   ╚══════╝╚═════╝    ╚═╝   [/bold yellow]
                      
[bold yellow]     D E V E L O P E D    B Y     Edoardo Manenti [ 0333574 | manenti000@gmail.com ]         [/bold yellow]

[bold yellow]Choose an option:[/bold yellow]
[bold yellow][1] Run Tests[/bold yellow]
[bold yellow][2] Show Plots[/bold yellow]
[bold yellow][3] Exit[/bold yellow]
""")
            choice = console.input("\n[bold yellow]>>> [/bold yellow]")
            if choice == "1":
                run_tests()
            elif choice == "2":
                generate_boxplots()
            elif choice == "3":
                #execute_command_ignore_error("make down", "make down before exiting")
                console.print("[bold green]Exiting... Goodbye![/bold green]")
                exit(0)
            else:
                console.print("[bold red]Invalid choice. Please try again.[/bold red]")
                wait_for_keypress()
    except KeyboardInterrupt:
        #execute_command_ignore_error("make down", "make down before exiting")
        console.print("\n[bold green]Exiting... Goodbye![/bold green]")
        exit(0)


if __name__ == "__main__":
    main_menu()