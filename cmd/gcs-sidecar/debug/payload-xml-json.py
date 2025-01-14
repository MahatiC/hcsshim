import json
import re
import xml.etree.ElementTree as ET

def parse_nested_json(data):
    """Recursively parse JSON strings within the JSON data structure."""
    if isinstance(data, str):
        # Try to parse the string as JSON
        try:
            parsed_data = json.loads(data)
            # Recursively parse deeper in case of nested JSON strings
            return parse_nested_json(parsed_data)
        except json.JSONDecodeError:
            # If not valid JSON, return the string as is
            return data
    elif isinstance(data, dict):
        # Recursively apply parsing to dictionary values
        return {key: parse_nested_json(value) for key, value in data.items()}
    elif isinstance(data, list):
        # Recursively apply parsing to list items
        return [parse_nested_json(item) for item in data]
    return data

def extract_payloads(xml_file, output_json_file="output.json"):
    payloads = []

    with open(xml_file, 'r') as file:
        lines = file.readlines()
        payload_lines = [line.strip() for line in lines if line.strip().startswith('<Data Name="payload">')]

    for line in payload_lines:
        payload_xml = re.sub(r'^<Data Name="payload">|</Data>$', '', line).strip()
        payload_json_str = payload_xml.replace("&quot;", '"')

        try:
            payload_dict = json.loads(payload_json_str)
            # Parse any nested JSON strings within the payload
            parsed_payload = parse_nested_json(payload_dict)
            payloads.append(parsed_payload)
        except json.JSONDecodeError:
            print(f"Skipping invalid JSON payload: {payload_json_str}")

    with open(output_json_file, 'w') as outfile:
        json.dump({"payloads": payloads}, outfile, indent=2)
    print(f"JSON data successfully written to {output_json_file}")

# Main Program
if __name__ == "__main__":
    xml_file = input("Enter the path of the XML file: ")
    output_json_file = input("Enter the desired name for the output JSON file (press Enter to use 'output.json'): ")

    # Set to "output.json" if no file name is provided
    if not output_json_file.strip():
        output_json_file = "output.json"

    extract_payloads(xml_file, output_json_file)
