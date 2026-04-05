import json
import csv
from utils.logger import logger
from utils.config import config

def export_json(results, filename):
    """
    Export scan results to a JSON file.
    """
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        logger.info(f"Results exported to {filename} (JSON)")
    except Exception as e:
        logger.error(f"Error exporting to JSON: {e}")

def export_csv(results, filename):
    """
    Export scan results to a CSV file.
    """
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'OS', 'Port', 'Protocol', 'State', 'Service'])
            
            for ip, data in results.items():
                os_guess = data.get('os', 'Unknown')
                for port_info in data.get('ports', []):
                    writer.writerow([
                        ip,
                        os_guess,
                        port_info.get('port', ''),
                        port_info.get('protocol', ''),
                        port_info.get('state', ''),
                        port_info.get('service', '')
                    ])
        logger.info(f"Results exported to {filename} (CSV)")
    except Exception as e:
        logger.error(f"Error exporting to CSV: {e}")

def export_markdown(results, filename):
    """
    Export scan results to a Markdown file.
    """
    try:
        with open(filename, 'w') as f:
            f.write('# Npocket Scan Report\n\n')
            
            for ip, data in results.items():
                f.write(f"## Host: {ip}\n")
                f.write(f"**OS Guess:** {data.get('os', 'Unknown')}\n\n")
                
                ports = data.get('ports', [])
                if ports:
                    f.write('| Port | Protocol | State | Service |\n')
                    f.write('|------|----------|-------|---------|\n')
                    for port_info in ports:
                        f.write(f"| {port_info.get('port', '')} | {port_info.get('protocol', '')} | {port_info.get('state', '')} | {port_info.get('service', '') or '-'} |\n")
                else:
                    f.write("*No open ports found.*\n")
                f.write('\n')
                
        logger.info(f"Results exported to {filename} (Markdown)")
    except Exception as e:
        logger.error(f"Error exporting to Markdown: {e}")

def export_html(results, filename):
    """
    Export scan results to a beautiful interactive HTML dashboard.
    """
    try:
        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Npocket Scan Dashboard</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e2e; color: #d4d4d4; margin: 0; padding: 20px; }
                h1 { color: #00e676; text-align: center; font-size: 2.5em; text-transform: uppercase; letter-spacing: 2px; }
                .container { max-width: 1000px; margin: 0 auto; }
                .host-card { background: #2d2d30; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); border-left: 5px solid #007acc; }
                .host-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #3e3e42; padding-bottom: 10px; margin-bottom: 15px; }
                .host-ip { font-size: 1.5em; font-weight: bold; color: #569cd6; }
                .os-guess { font-size: 1em; background: #3e3e42; padding: 5px 10px; border-radius: 4px; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #3e3e42; }
                th { background-color: #252526; color: #9cdcfe; font-weight: normal; }
                tr:hover { background-color: #333337; }
                .state-open { color: #00e676; font-weight: bold; }
                .state-filtered { color: #ffb86c; font-weight: bold; }
                .state-closed { color: #f44747; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Npocket Dashboard</h1>
        """
        
        for ip, data in results.items():
            os_guess = data.get('os', 'Unknown')
            html_content += f"""
                <div class="host-card">
                    <div class="host-header">
                        <div class="host-ip">🎯 {ip}</div>
                        <div class="os-guess">💻 OS: {os_guess}</div>
                    </div>
            """
            
            ports = data.get('ports', [])
            if ports:
                html_content += """
                    <table>
                        <thead>
                            <tr>
                                <th>Port/Proto</th>
                                <th>State</th>
                                <th>Service Info</th>
                            </tr>
                        </thead>
                        <tbody>
                """
                for p in ports:
                    port_proto = f"{p.get('port', '')}/{p.get('protocol', '')}"
                    state = p.get('state', '')
                    service = p.get('service', '') or '-'
                    state_class = f"state-{state.lower()}"
                    
                    html_content += f"""
                            <tr>
                                <td>{port_proto}</td>
                                <td class="{state_class}">{state}</td>
                                <td>{service}</td>
                            </tr>
                    """
                html_content += """
                        </tbody>
                    </table>
                """
            else:
                html_content += "<p style='color: #ffb86c;'><i>No open ports found.</i></p>"
                
            html_content += "</div>"
            
        html_content += """
            </div>
        </body>
        </html>
        """
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        logger.info(f"Results exported to {filename} (HTML)")
    except Exception as e:
        logger.error(f"Error exporting to HTML: {e}")

def export_results(results):
    """
    Export results based on configuration.
    """
    if config.output_file:
        if config.output_format.lower() == 'json':
            export_json(results, config.output_file)
        elif config.output_format.lower() == 'csv':
            export_csv(results, config.output_file)
        elif config.output_format.lower() == 'md':
            export_markdown(results, config.output_file)
        elif config.output_format.lower() == 'html':
            export_html(results, config.output_file)
        else:
            logger.warning(f"Unsupported export format: {config.output_format}")
