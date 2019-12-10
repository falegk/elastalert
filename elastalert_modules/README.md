## cg_alerting_modules
[ElastAlert](https://github.com/Yelp/elastalert) extension modules for CG Apps

## Install Custom Alerts & Rule Types

### STEP 0: Prepare (Install ElastAlert - Tested for v0.1.21)
http://elastalert.readthedocs.io/en/latest/running_elastalert.html

- Clone elastalert `$ git clone https://github.com/Yelp/elastalert.git /opt/elastalert`
- cd /opt/elastalert and then:
    ```
    $ pip install "setuptools>=11.3"
    $ python setup.py install
    ```
- Depending on the version of Elasticsearch, you may need to manually install the correct version of elasticsearch-py.
Elasticsearch 5.0+: `$ pip install "elasticsearch>=5.0.0"`
- Open config.yaml.example and set below options. Then save file as config.yaml
    - rules_folder:
    - es_host: {elasticsearch host}
    - es_port: {elasticsearch port}
    - ...other options
- Create an index for ElastAlert `$ elastalert-create-index`


### STEP 1: Create folders & files
- Clone this repo into elastalert dir (new dir elastalert_modules): `git clone https://github.com/clonesec/cg_alerting_modules.git elastalert_modules`


### STEP 2: Add custom modules to ElastAlert
- Install [jinja2](http://jinja.pocoo.org/docs/2.10/intro): `pip install Jinja2`
- Backup the elastalert/config.py file: cp config.py config-backup.py
- Open the elastalert/config.py file
- Import modules folder:
    ```
    sys.path.append('/opt/elastalert/elastalert_modules') # Add your absolute path
    import elastalert_modules
    from elastalert_modules import extended_rules
    from elastalert_modules import extended_alerts
    ```

    (* add these lines to the beginning of the file where all imports are made)
- Add all custom rule types to rules_mapping dict:
    ```
    # Used to map the names of rules to their classes
    rules_mapping = {
        'frequency': ruletypes.FrequencyRule,
        'any': ruletypes.AnyRule,
        ... OTHER RULE TYPES ...,
        'extension_cardinality': elastalert_modules.extended_rules.ExtensionCardinalityRule,
        'extension_frequency': elastalert_modules.extended_rules.ExtensionFrequencyRule
    }
    ```
    the last two lines are the ones to be added.

- Add all custom alerts to alerts_mapping dict:
    ```
    alerts_mapping = {
        'email': alerts.EmailAlerter,
        ... OTHER ALERTS ...
        'create_incident': elastalert_modules.extended_alerts.CreateIncident,
        'clone_email': elastalert_modules.extended_alerts.CloneEmail
    }
    ```

- In `elastalert/schema.yaml` add this under `oneOf:` section (attention to syntax of the file)
    ```
  - title: Extension Cardinality
    required: [cardinality_field, timeframe]
    properties:
      type: {enum: [extension_cardinality]}
      min_num_events: {type: integer}
      max_num_events: {type: integer}
      timeframe: *timeframe
      attach_related: {type: boolean}

  - title: Extension Frequency
    required: [timeframe]
    properties:
      type: {enum: [extension_frequency]}
      min_num_events: {type: integer}
      max_num_events: {type: integer}
      timeframe: *timeframe
      use_count_query: {type: boolean}
      doc_type: {type: string}
      use_terms_query: {type: boolean}
      terms_size: {type: integer}
      attach_related: {type: boolean}
    ```

__* Make sure the names and paths of folders and files are correct, otherwise elastalert will not start.__

#### Run for testing
cd /opt/elastalert and run
`python -m elastalert.elastalert --verbose`

[Running ElastAlert - Official Doc.](http://elastalert.readthedocs.io/en/latest/elastalert.html#running-elastalert)

### STEP 3: Run Elastalert as service
Copy the file elastalert-extras/elastalert-server.service to /lib/systemd/system/elastalert-server.service

- Create Link:
  `ln -s /lib/systemd/system/elastalert-server.service /etc/systemd/system/elastalert-server.service`

- Reload Daemon:
  `systemctl daemon-reload`

- Enable Service and Start Service:
    ```
        systemctl enable elastalert-server.service
        systemctl start elastalert-server.service
        systemctl status elastalert-server.service
    ```

- Useful commands
    - Real Time logs: `sudo journalctl -f -u elastalert-server.service`


## Using Custom modules

### Use Custom Rule Types
In rule files, specify the type with the rule type you want to use.

Existing Custom Types:
- extension_cardinality
- extension_frequency

### Use Custom Alerts
In the rule file, specify the alert with the custom alert you want to use.

Existing Custom Alerts
- create_incident
- clone_email

Example:
```
alert:
- create_incident
- email

```
