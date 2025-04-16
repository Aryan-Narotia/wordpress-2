import json

def get_highest_severity(vulnerabilities):
    """Return the highest severity: high > medium > low."""
    severity_levels = ['low', 'medium', 'high']
    found = set()

    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'low').lower()
        if severity in severity_levels:
            found.add(severity)

    if 'high' in found:
        return 'high'
    elif 'medium' in found:
        return 'medium'
    elif 'low' in found:
        return 'low'
    else:
        return 'low'

def parse_wpscan_output(wpscan_output_file):
    """Parse WPScan JSON and return plugin name + highest severity."""
    with open(wpscan_output_file, 'r') as f:
        data = json.load(f)

    print("\n✅ Loaded WPScan JSON output")
    print("🔍 Plugins section:")
    print(json.dumps(data.get('plugins', {}), indent=2))

    plugins_data = []

    if 'plugins' in data and isinstance(data['plugins'], dict):
        for plugin_name, plugin_info in data['plugins'].items():
            print(f"\n📦 Found plugin: {plugin_name}")
            vulnerabilities = plugin_info.get('vulnerabilities', [])
            print(f"  - Vulnerabilities: {len(vulnerabilities)}")

            if vulnerabilities:
                severity = get_highest_severity(vulnerabilities)
                plugins_data.append((plugin_name, severity))

    print(f"\n Total plugins with vulnerabilities: {len(plugins_data)}")
    return plugins_data

def save_to_txt(output_file, plugins):
    """Write plugin name and severity to a text file."""
    with open(output_file, 'w') as f:
        if not plugins:
            f.write("No plugin vulnerabilities found.\n")
            print(" No vulnerabilities found — writing fallback message.")
        else:
            for name, severity in plugins:
                f.write(f"Plugin Name: {name}\n")
                f.write(f"Severity: {severity}\n\n")

if __name__ == '__main__':
    wpscan_output_file = 'wpscan-results.json'
    output_txt_file = 'plugin_vulnerabilities.txt'

    plugins = parse_wpscan_output(wpscan_output_file)
    save_to_txt(output_txt_file, plugins)

    print(f"\nTXT report generated: {output_txt_file}")
