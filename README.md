# splat

## Installation

1. Clone the repository.

```bash
git clone https://github.com/boltanalytics/splat.git
```

2. Install the package. We recommend creating and activating a virtual environment before
installing.
```bash
cd splat
python setup.py install
```

3. Verify the installation. Running the following command should not result in an exception.
```bash
python -c "import splat"
```

## Running `splat`

To know the options supported by `splat` and view some examples, look at the help page using:
```bash
splat --help
```

`splat` expects information about the Splunk server to be supplied as a JSON file. It 
should have the following format:
```json
{
  "host": "1.1.1.1",
  "port": "8089",
  "username": "username",
  "password": "password",
  "owner": "owner",
  "app": "app"
}
```

4 options are mandatory for running `splat`. They include
- `-sc` / `--splunk-config` which is the path to the JSON file holding Splunk configuration.
- `-i` is the Splunk index to query.
- `-st` is the start time of the query.
- `-et` is the end time of the query.

Here is an example of a query:
```bash
splat -sc splunk.json -i firewall -st -5m -et now -v
```

When run successfully, the output should look as follows:
```
Input data size: 2341.37 KBs
Output data size: 1843.36 KBs
Estimated compression: 21.27%
```