import os
import shutil
import subprocess
import pandas as pd
import matplotlib.pyplot as plt
from rich.console import Console
from rich.table import Table

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
    main_menu()


def is_module_mounted():
    """Check if the module is mounted by verifying the existence of refmon_test_run."""
    return os.path.exists(test_executable)


def execute_test(executable):
    """Execute a test executable with taskset and chrt."""
    try:
        subprocess.run(["taskset", "0x2", "sudo", "chrt", "90", executable], check=True)
    except FileNotFoundError:
        console.print(f"[bold red]Error: {executable} not found. Ensure it is compiled and available.[/bold red]")
        wait_for_keypress()
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Test execution failed with error: {e}[/bold red]")
        wait_for_keypress()


def run_baseline_tests():
    """Run the baseline test 200 times before the module is mounted."""
    if is_module_mounted():
        console.print("[bold red]Cannot run baseline tests: the module is mounted.[/bold red]")
        wait_for_keypress()
        return

    console.print("[bold green]Starting 200 baseline runs...[/bold green]")
    raw_data = []

    # Execute baseline test 200 times
    for run in range(1, 201):
        console.print(f"Run {run}/200...")
        execute_test(baseline_executable)
        if os.path.exists(baseline_csv):
            baseline_df = pd.read_csv(baseline_csv)
            raw_data.append(["WITHOUT_MODULE", baseline_df.iloc[0]["Read Time (cycles)"], baseline_df.iloc[0]["Write Time (cycles)"]])

    # Save results to rawResults.csv
    raw_df = pd.DataFrame(raw_data, columns=["N", "Read Time (cycles)", "Write Time (cycles)"])
    raw_df.to_csv(raw_results_file, index=False)
    console.print(f"[bold green]Baseline test results saved to {raw_results_file}[/bold green]")


def perform_tests():
    """Perform 200 runs for the refmon test."""
    if not os.path.exists(raw_results_file):
        console.print("[bold yellow]Baseline results missing. Run baseline tests first.[/bold yellow]")
        wait_for_keypress()
        return

    if not is_module_mounted():
        console.print("[bold red]Module not mounted. Please mount the module to proceed.[/bold red]")
        console.print("[bold cyan]Press Enter once the module is mounted...[/bold cyan]")
        input()
        if not is_module_mounted():
            console.print("[bold red]Module still not mounted. Aborting test execution.[/bold red]")
            wait_for_keypress()
            return

    console.print("[bold green]Starting 200 refmon runs...[/bold green]")
    raw_data = []

    # Load existing data from rawResults.csv
    if os.path.exists(raw_results_file):
        raw_data = pd.read_csv(raw_results_file).values.tolist()

    # Execute refmon test 200 times
    for run in range(1, 201):
        console.print(f"Run {run}/200...")
        execute_test(test_executable)
        if os.path.exists(test_results_csv):
            test_df = pd.read_csv(test_results_csv)
            for _, row in test_df.iterrows():
                raw_data.append([row["N"], row["Read Time (cycles)"], row["Write Time (cycles)"]])

    # Save updated results
    raw_df = pd.DataFrame(raw_data, columns=["N", "Read Time (cycles)", "Write Time (cycles)"])
    raw_df.to_csv(raw_results_file, index=False)
    console.print(f"[bold green]Test results saved to {raw_results_file}[/bold green]")


def generate_boxplots():
    """Generate boxplots directly from raw results without outliers."""
    if not os.path.exists(raw_results_file):
        console.print("[bold yellow]Raw results file missing. Perform tests first.[/bold yellow]")
        wait_for_keypress()
        return

    try:
        raw_df = pd.read_csv(raw_results_file)

        # Ensure graphs directory is clean
        if os.path.exists(graphs_dir):
            shutil.rmtree(graphs_dir)
        os.makedirs(graphs_dir)

        # Determine global Y-axis limits
        global_min = min(raw_df["Read Time (cycles)"].min(), raw_df["Write Time (cycles)"].min())
        global_max = max(raw_df["Read Time (cycles)"].max(), raw_df["Write Time (cycles)"].max())

        for col in ["Read Time (cycles)", "Write Time (cycles)"]:
            plt.figure(figsize=(12, 8))

            # Extract unique values of N and group data
            unique_n = raw_df["N"].unique()
            grouped_data = [raw_df[raw_df["N"] == n][col] for n in unique_n]

            # Generate boxplot
            # plt.boxplot(grouped_data, showfliers=False, patch_artist=True, tick_labels=unique_n)
            # plt.title(f"Boxplot of {col} by Number of protected files (Outliers Removed)")
            plt.boxplot(grouped_data, showfliers=True, patch_artist=True, labels=unique_n)
            plt.title(f"Boxplot of {col} by Number of protected files")
            plt.xlabel("Number of protected files")
            plt.ylabel(col)
            # plt.ylim(1.5e3, 5e3)
            plt.ylim(global_min, global_max)  # Set consistent Y-axis limits
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

def main_menu():
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
""")
        console.print("[bold yellow]Choose an option:[/bold yellow]")
        console.print("[bold yellow][1] Run Baseline Tests[/bold yellow]")
        console.print("[bold yellow][2] Perform RefMon Tests[/bold yellow]")
        console.print("[bold yellow][3] Generate and Show Boxplots[/bold yellow]")
        console.print("[bold yellow][4] Exit[/bold yellow]")

        choice = console.input("\n[bold yellow]>>> [/bold yellow]")
        if choice == "1":
            run_baseline_tests()
        elif choice == "2":
            perform_tests()
        elif choice == "3":
            generate_boxplots()
        elif choice == "4":
            console.print("[bold green]Exiting... Goodbye![/bold green]")
            exit(0)
        else:
            console.print("[bold red]Invalid choice. Please try again.[/bold red]")
            wait_for_keypress()


if __name__ == "__main__":
    main_menu()
