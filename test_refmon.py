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
    # Run `make down` before baseline tests
    execute_command_ignore_error("make down", "make down")

    console.print("[bold green]Starting baseline tests...[/bold green]")
    raw_data = []

    # Execute baseline test 200 times
    for run in range(1, 201):
        console.print(f"Run {run}/200...")
        if not execute_test(baseline_executable):
            return
        if os.path.exists(baseline_csv):
            baseline_df = pd.read_csv(baseline_csv)
            raw_data.append(["WITHOUT_MODULE", baseline_df.iloc[0]["Read Time (cycles)"], baseline_df.iloc[0]["Write Time (cycles)"], baseline_df.iloc[0]["Create Time (cycles)"]])

    # Save baseline results to rawResults.csv
    raw_df = pd.DataFrame(raw_data, columns=["N", "Read Time (cycles)", "Write Time (cycles)", "Create Time (cycles)"])
    raw_df.to_csv(raw_results_file, index=False)
    console.print(f"[bold green]Baseline test results saved to {raw_results_file}[/bold green]")

    # Run `make up` before RefMon tests
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
                raw_data.append([row["N"], row["Read Time (cycles)"], row["Write Time (cycles)"], row["Create Time (cycles)"]])

    # Save updated results
    raw_df = pd.DataFrame(raw_data, columns=["N", "Read Time (cycles)", "Write Time (cycles)", "Create Time (cycles)"])
    raw_df.to_csv(raw_results_file, index=False)
    console.print(f"[bold green]Test results saved to {raw_results_file}[/bold green]")

    # Generate and show boxplots
    generate_boxplots()


def generate_boxplots():
    """Generate boxplots directly from raw results."""
    if not os.path.exists(raw_results_file):
        console.print("[bold yellow]Raw results file missing. Perform tests first.[/bold yellow]")
        wait_for_keypress()
        return
    
    lower_bound_y, upper_bound_y, show_outliers = get_graph_preferences()

    try:
        raw_df = pd.read_csv(raw_results_file)

        # Ensure graphs directory is clean
        if os.path.exists(graphs_dir):
            shutil.rmtree(graphs_dir)
        os.makedirs(graphs_dir)

        # Determine global Y-axis limits

        # Determine global Y-axis limits if not specified
        if lower_bound_y == -1 or upper_bound_y == -1:
            lower_bound_y = min(raw_df["Read Time (cycles)"].min(), raw_df["Write Time (cycles)"].min(), raw_df["Create Time (cycles)"].min())
            upper_bound_y = max(raw_df["Read Time (cycles)"].max(), raw_df["Write Time (cycles)"].max(), raw_df["Create Time (cycles)"].max())

        for col in ["Read Time (cycles)", "Write Time (cycles)", "Create Time (cycles)"]:
            plt.figure(figsize=(12, 8))

            # Extract unique values of N and group data
            unique_n = raw_df["N"].unique()
            grouped_data = [raw_df[raw_df["N"] == n][col] for n in unique_n]

            # Generate boxplot
            plt.boxplot(grouped_data, showfliers=show_outliers, patch_artist=True, tick_labels=unique_n)
            plt.title(f"Boxplot of {col} by Number of Protected Files")
            plt.xlabel("Number of Protected Files")
            plt.ylabel(col)
            plt.ylim(lower_bound_y, upper_bound_y)
            plt.grid(True)

            # Save the boxplot
            output_path = os.path.join(graphs_dir, f"{col.replace(' ', '_')}_boxplot.png")
            plt.savefig(output_path)

            console.print(f"[bold green]Boxplot for {col} saved to {output_path}[/bold green]")

        # Display the plots
        plt.show()

    except Exception as e:
        console.print(f"[bold red]Failed to generate boxplots: {e}[/bold red]")
        wait_for_keypress()

def get_graph_preferences():
    """Prompt the user for custom Y-axis limits and outliers or default behavior."""
    lower_bound = -1
    upper_bound = -1
    outliers = True
    console.print("[bold yellow]Do you want to specify custom Y-axis limits for the graphs? (y/n)[/bold yellow]")
    choice = console.input("[bold yellow]>>> [/bold yellow]").strip().lower()
    if choice == "y":
        try:
            lower_bound = float(console.input("[bold yellow]Enter the lower bound for Y-axis: [/bold yellow]"))
            upper_bound = float(console.input("[bold yellow]Enter the upper bound for Y-axis: [/bold yellow]"))
        except ValueError:
            console.print("[bold red]Invalid input! Using default Y-axis limits.[/bold red]")
    console.print("[bold yellow]Do you want to show outliers in the graphs? (y/n)[/bold yellow]")
    choice = console.input("[bold yellow]>>> [/bold yellow]").strip().lower()
    if choice == "n":
        try:
            outliers = False
        except ValueError:
            console.print("[bold red]Invalid input! Showing outliers as default.[/bold red]")
    return lower_bound, upper_bound, outliers

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
        execute_command_ignore_error("make down", "make down before exiting")
        console.print("\n[bold green]Exiting... Goodbye![/bold green]")
        exit(0)


if __name__ == "__main__":
    main_menu()