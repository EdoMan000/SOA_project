import os
import shutil
import subprocess
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
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
final_measurements_file = os.path.join(results_dir, "finalMeasurements.csv")
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
    """Execute a test executable."""
    try:
        subprocess.run(["sudo", executable], check=True)
    except FileNotFoundError:
        console.print(f"[bold red]Error: {executable} not found. Ensure it is compiled and available.[/bold red]")
        wait_for_keypress()
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Test execution failed with error: {e}[/bold red]")
        wait_for_keypress()


def run_baseline_tests():
    """Run the baseline test 100 times before the module is mounted."""
    if is_module_mounted():
        console.print("[bold red]Cannot run baseline tests: the module is mounted.[/bold red]")
        wait_for_keypress()
        return

    console.print("[bold green]Starting 100 baseline runs...[/bold green]")
    raw_data = []

    # Execute baseline test 100 times
    for run in range(1, 101):
        console.print(f"Run {run}/100...")
        execute_test(baseline_executable)
        if os.path.exists(baseline_csv):
            baseline_df = pd.read_csv(baseline_csv)
            raw_data.append(["BASELINE", baseline_df.iloc[0]["Read Time (cycles)"], baseline_df.iloc[0]["Write Time (cycles)"]])

    # Save results to rawResults.csv
    raw_df = pd.DataFrame(raw_data, columns=["N", "Read Time (cycles)", "Write Time (cycles)"])
    raw_df.to_csv(raw_results_file, index=False)
    console.print(f"[bold green]Baseline test results saved to {raw_results_file}[/bold green]")


def perform_tests():
    """Perform 100 runs for the refmon test."""
    if not os.path.exists(raw_results_file):
        console.print("[bold yellow]Baseline results missing. Run baseline tests first.[/bold yellow]")
        wait_for_keypress()
        return

    if not is_module_mounted():
        console.print("[bold yellow]Module not mounted. Please mount the module to proceed.[/bold yellow]")
        console.print("[bold cyan]Press Enter once the module is mounted...[/bold cyan]")
        input()
        if not is_module_mounted():
            console.print("[bold red]Module still not mounted. Aborting test execution.[/bold red]")
            wait_for_keypress()
            return

    console.print("[bold green]Starting 100 refmon runs...[/bold green]")
    raw_data = []

    # Load existing data from rawResults.csv
    if os.path.exists(raw_results_file):
        raw_data = pd.read_csv(raw_results_file).values.tolist()

    # Execute refmon test 100 times
    for run in range(1, 101):
        console.print(f"Run {run}/100...")
        execute_test(test_executable)
        if os.path.exists(test_results_csv):
            test_df = pd.read_csv(test_results_csv)
            for _, row in test_df.iterrows():
                raw_data.append([row["N"], row["Read Time (cycles)"], row["Write Time (cycles)"]])

    # Save updated results
    raw_df = pd.DataFrame(raw_data, columns=["N", "Read Time (cycles)", "Write Time (cycles)"])
    raw_df.to_csv(raw_results_file, index=False)
    console.print(f"[bold green]Test results saved to {raw_results_file}[/bold green]")


def remove_outliers_and_aggregate():
    """Remove outliers and calculate final statistics."""
    if not os.path.exists(raw_results_file):
        console.print("[bold yellow]No raw results found. Perform tests first...[/bold yellow]")
        wait_for_keypress()
        return

    console.print("[bold green]Processing raw results to remove outliers and compute statistics...[/bold green]")
    try:
        raw_df = pd.read_csv(raw_results_file)
        final_rows = []

        for label, group in raw_df.groupby("N"):
            for col in ["Read Time (cycles)", "Write Time (cycles)"]:
                data = group[col]

                # Remove outliers using IQR
                q1, q3 = np.percentile(data, [25, 75])
                iqr = q3 - q1
                filtered_data = data[(data >= q1 - 1.5 * iqr) & (data <= q3 + 1.5 * iqr)]

                # Compute statistics
                final_rows.append({
                    "N": label,
                    f"Average {col}": filtered_data.mean(),
                    f"Median {col}": filtered_data.median(),
                    f"Std Dev {col}": filtered_data.std()
                })

        # Convert to DataFrame and save final measurements
        final_df = pd.DataFrame(final_rows)
        final_df.to_csv(final_measurements_file, index=False)
        console.print(f"[bold green]Final measurements saved to {final_measurements_file}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to process results: {e}[/bold red]")
        wait_for_keypress()


def generate_boxplots():
    """Generate boxplots from raw results with outliers optionally removed."""
    if not os.path.exists(raw_results_file):
        console.print("[bold yellow]Raw results missing. Perform tests first...[/bold yellow]")
        wait_for_keypress()
        return

    try:
        raw_df = pd.read_csv(raw_results_file)

        # Ensure graphs directory is clean
        if os.path.exists(graphs_dir):
            shutil.rmtree(graphs_dir)
        os.makedirs(graphs_dir)

        # Create boxplots for Read and Write Times
        for col in ["Read Time (cycles)", "Write Time (cycles)"]:
            plt.figure(figsize=(10, 6))

            # Group data by "N"
            grouped_data = [group[col].values for _, group in raw_df.groupby("N")]

            plt.boxplot(
                grouped_data, showfliers=False, patch_artist=True,
                tick_labels=raw_df["N"].unique()
            )
            plt.title(f"Boxplot of {col} by N (Outliers Removed)")
            plt.xlabel("N (Number of Protected Files)")
            plt.ylabel(col)
            plt.grid(True)

            # Save the boxplot
            output_path = os.path.join(graphs_dir, f"{col.replace(' ', '_')}_boxplot.png")
            plt.savefig(output_path)

        console.print(f"[bold green]Boxplots generated and saved in '{graphs_dir}'[/bold green]")
        plt.show()
    except Exception as e:
        console.print(f"[bold red]Failed to generate boxplots: {e}[/bold red]")
        wait_for_keypress()


def display_results():
    """Display final results in a table."""
    if not os.path.exists(final_measurements_file):
        console.print("[bold yellow]Final measurements missing. Aggregating results first...[/bold yellow]")
        remove_outliers_and_aggregate()

    try:
        df = pd.read_csv(final_measurements_file)
        table = Table(title="Final Refmon Test Results")

        table.add_column("N", justify="left")
        table.add_column("Average Read Time (cycles)", justify="right")
        table.add_column("Median Read Time (cycles)", justify="right")
        table.add_column("Std Dev Read Time (cycles)", justify="right")
        table.add_column("Average Write Time (cycles)", justify="right")
        table.add_column("Median Write Time (cycles)", justify="right")
        table.add_column("Std Dev Write Time (cycles)", justify="right")

        for _, row in df.iterrows():
            table.add_row(
                str(row["N"]),
                f"{int(row['Average Read Time (cycles)'])}",
                f"{int(row['Median Read Time (cycles)'])}",
                f"{int(row['Std Dev Read Time (cycles)'])}",
                f"{int(row['Average Write Time (cycles)'])}",
                f"{int(row['Median Write Time (cycles)'])}",
                f"{int(row['Std Dev Write Time (cycles)'])}"
            )

        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Failed to read results: {e}[/bold red]")
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
        console.print("[bold yellow][2] Perform Tests[/bold yellow]")
        console.print("[bold yellow][3] Display Results[/bold yellow]")
        console.print("[bold yellow][4] Generate Boxplots[/bold yellow]")
        console.print("[bold yellow][5] Exit[/bold yellow]")

        choice = console.input("\n[bold yellow]>>> [/bold yellow]")
        if choice == "1":
            run_baseline_tests()
        elif choice == "2":
            perform_tests()
        elif choice == "3":
            display_results()
        elif choice == "4":
            generate_boxplots()
        elif choice == "5":
            console.print("[bold green]Exiting... Goodbye![/bold green]")
            exit(0)
        else:
            console.print("[bold red]Invalid choice. Please try again.[/bold red]")
            wait_for_keypress()


if __name__ == "__main__":
    main_menu()
