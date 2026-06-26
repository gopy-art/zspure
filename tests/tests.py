import os
import subprocess
import sys
import argparse

def run_script(test_type):
    if test_type == 'integration':
        script_name = 'integration'
    elif test_type == 'unit':
        script_name = 'unit'
    else:
        print(f"Error: Unknown test type '{test_type}'")
        return
    
    # detect the operating system
    if sys.platform.startswith('win'):
        # windows
        bat_file = f'tests\\{script_name}\\{script_name}.bat'
        if os.path.exists(bat_file):
            print(f"Running Windows {script_name} tests...")
            subprocess.call([bat_file], shell=True)
        else:
            print(f"Error: {bat_file} not found!")
            
    elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
        # mac_os/linux
        sh_file = f'./tests/{script_name}/{script_name}.sh'
        if os.path.exists(sh_file):
            print(f"Running Linux {script_name} tests...")
            os.chmod(sh_file, 0o755)
            subprocess.call(['bash', sh_file])
        else:
            print(f"Error: {sh_file} not found!")
    
    else:
        print(f"Unsupported OS: {sys.platform}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run Tests')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--integration', action='store_true', help='Run integration tests')
    group.add_argument('--unit', action='store_true', help='Run unit tests')
    args = parser.parse_args()
    
    if args.integration:
        run_script('integration')
    elif args.unit:
        run_script('unit')