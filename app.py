import dash
from dash import dcc, html, Input, Output, State
import dash_bootstrap_components as dbc
from dash.exceptions import PreventUpdate

# Initialize the Dash app
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])

# Define parameters and actions based on the HELP section
parameter_options = {
    'CLDSSN': {'range': '0-255'},
    'CLDTRANSTYPE': {'range': '0-255'},
    'CLDNUMPLAN': {'options': ['UNKNOWN', 'ISDN', 'GENERIC', 'DATA', 'TELEX', 'MARITIME', 'LAND_MOBILE', 'ISDN_MOBILE', 'PRIVATE']},
    'CLDPARTYADDR': {'type': 'Hexadecimal digits'},
    'CLDNATOFADDR': {'options': ['UNKNOWN', 'SUBSCRIBER', 'RESERVE', 'NATIONAL', 'INTERNATIONAL']},
    'CLDGTFORMAT': {'range': '1-4 for ITU and 1-2 for ANSI'},
    'CLGSSN': {'range': '0-255'},
    'CLGTRANSTYPE': {'range': '0-255'},
    'CLGNUMPLAN': {'options': ['UNKNOWN', 'ISDN', 'GENERIC', 'DATA', 'TELEX', 'MARITIME', 'LAND_MOBILE', 'ISDN_MOBILE', 'PRIVATE']},
    'CLGPARTYADDR': {'type': 'Hexadecimal digits'},
    'CLGNATOFADDR': {'options': ['UNKNOWN', 'SUBSCRIBER', 'RESERVE', 'NATIONAL', 'INTERNATIONAL']},
    'CLGGTFORMAT': {'range': '1-4 for ITU and 1-2 for ANSI'},
    'FORBIDDENPARAM': {'options': ['CD_PARTY_NUM', 'CG_PARTY_NUM', 'CG_PARTY_CATEGORY', 'CALL_REFERENCE_NUM', 'MSC_ADDRESS', 'VLR_NUM', 'LOC_NUM', 'IMEI', 'IMSI', 'LMSI', 'VLR_CAPABILITY', 'SUBS_STATE', 'CURRENT_LOC', 'REQ_DOMAIN', 'MSC_NUM', 'LOC_INFO', 'MSISDN']},
    'OPCODE': {'options': ['UPDATE_LOCATION', 'INSERT_SUBSCRIBER_DATA', 'SEND_ROUTING_INFO', 'SEND_ROUTING_INFO_FOR_SM', 'ANY_TIME_INTERROGATION', 'INITIAL_DP', 'DELETE_SUBSCRIBER_DATA', 'SEND_PARAMETERS', 'CHECK_IMEI', 'SEND_AUTHENTICATION_INFO', 'SEND_IMSI', 'MT_FORWARD_SM', 'MO_FWD_SM', 'REPORT_SM_DELIVERY_STATUS', 'ALERT_SERVICE_CENTER_WITHOUT_RESULT', 'INFORM_SERVICE_CENTER', 'ALERT_SERVICE_CENTER', 'READY_FOR_SM', 'PURGE_FOR_SM', 'CANCEL_LOCATION', 'PROVIDE_ROAMING_NUM', 'USSD', 'PUSSR', 'INTERROGATE_SS', 'AUTHENTICATION_FAILURE_REPORT', 'UPDATE_GPRS_LOCATION', 'PROVIDE_SUBSCRIBER_INFO']},
    'TCAPDLGTYPE': {'options': ['BEGIN', 'CONTINUE', 'END', 'ABORT', 'UNIDIRECTIONAL']},
    'ACN': {'type': 'ACN String'},
    'TCAPCOMPTYPE': {'options': ['INVOKE', 'RETURNRESLAST', 'RETURNRESNOTLAST', 'RETURNERROR', 'REJECT']},
    'IMSI': {'type': 'Numeric, Max Length 16'},
    'MSISDN': {'type': 'Numeric, Max Length 18'},
    'VLRADDR': {'type': 'Numeric, Max Length 18'},
    'SCADDR': {'type': 'Numeric, Max Length 18'},
    'HLRNUMBER': {'type': 'Numeric, Max Length 18'},
    'SERVICEKEY': {'type': 'Numeric, 0-2147483647'},
    'SMSRCADDR': {'type': 'Numeric, Max Length 18'},
    'SMDSTADDR': {'type': 'Numeric, Max Length 18'},
    'IS_LONG_SMS': {'options': ['TRUE', 'FALSE']},
    'MAP_VERSION': {'options': ['1', '2', '3']},
    'SMTPOAADDR': {'type': 'Numeric/Alphabet, Max Length 18'},
    'SMTPDAADDR': {'type': 'Numeric, Max Length 18'},
    'MTI': {'options': ['SMS_SUBMIT', 'SMS_DELIVER', 'SMS_STATUS_REPORT']}
}

action_options = {
    'MATCH': {'routes': ['BLOCK_MSG', 'ALLOW_MSG']},
    'UNMATCH': {'routes': ['BLOCK_MSG', 'ALLOW_MSG']}
}

# Layout of the app
app.layout = dbc.Container([
    html.H1("Rule Management Dashboard"),
    dbc.Button("Add Rule", id="open-add-rule-modal", color="primary"),
    html.Div(id="rules-container", className="mt-3"),

    # Add Rule Modal
    dbc.Modal([
        dbc.ModalHeader("Add Rule"),
        dbc.ModalBody([
            dbc.Row([
                dbc.Col([
                    dbc.Label("Rule Name"),
                    dbc.Input(id="rule-name-input", placeholder="Enter rule name"),
                ])
            ]),
            html.Div([
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Select Parameters"),
                        dcc.Dropdown(
                            id="parameter-dropdown",
                            options=[{'label': param, 'value': param} for param in parameter_options.keys()],
                            multi=True,
                            placeholder="Select parameters"
                        ),
                        html.Div(id="parameter-inputs-container")
                    ])
                ]),
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Select Actions"),
                        dcc.Dropdown(
                            id="action-dropdown",
                            options=[{'label': action, 'value': action} for action in action_options.keys()],
                            multi=True,
                            placeholder="Select actions"
                        ),
                        html.Div(id="action-inputs-container")
                    ])
                ]),
            ], style={'overflowY': 'scroll', 'maxHeight': '300px'}),
        ]),
        dbc.ModalFooter([
            dbc.Button("Save", id="save-rule-button", color="primary"),
            dbc.Button("Cancel", id="close-add-rule-modal", color="secondary", className="ml-2")
        ]),
    ], id="add-rule-modal", is_open=False),
])

# Store rules in a global list
rules = []

# Callback to toggle add rule modal
@app.callback(
    Output("add-rule-modal", "is_open"),
    [Input("open-add-rule-modal", "n_clicks"), Input("close-add-rule-modal", "n_clicks"), Input("save-rule-button", "n_clicks")],
    [State("add-rule-modal", "is_open")]
)
def toggle_add_rule_modal(open_click, close_click, save_click, is_open):
    if open_click or close_click or save_click:
        return not is_open
    return is_open

# Callback to dynamically add parameter inputs based on dropdown selection
@app.callback(
    Output("parameter-inputs-container", "children"),
    [Input("parameter-dropdown", "value")]
)
def update_parameter_inputs(selected_parameters):
    if selected_parameters:
        inputs = []
        for param in selected_parameters:
            param_info = parameter_options.get(param, {})
            options = param_info.get('options', [])
            input_type = 'options' if options else 'text'
            dropdown = dcc.Dropdown(
                id={'type': 'parameter-value-dropdown', 'index': param},
                options=[{'label': opt, 'value': opt} for opt in options],
                placeholder=f"Select value for {param}",
                multi=True,  # Added multi-select option
                clearable=True  # Added clearable option
            ) if input_type == 'options' else dbc.Input(
                id={'type': 'parameter-value-input', 'index': param},
                placeholder=f"Enter value for {param}"
            )
            inputs.append(
                dbc.Row([
                    dbc.Col([
                        dbc.Label(f"Value for {param}"),
                        dropdown
                    ])
                ])
            )
        return inputs
    return []

# Callback to dynamically add action inputs based on dropdown selection
@app.callback(
    Output("action-inputs-container", "children"),
    [Input("action-dropdown", "value")]
)
def update_action_inputs(selected_actions):
    if selected_actions:
        inputs = []
        for action in selected_actions:
            action_info = action_options.get(action, {})
            routes = action_info.get('routes', [])
            dropdown = dcc.Dropdown(
                id={'type': 'action-value-dropdown', 'index': action},
                options=[{'label': route, 'value': route} for route in routes],
                placeholder=f"Select route for {action}",
                multi=True,  # Added multi-select option
                clearable=True  # Added clearable option
            )
            inputs.append(
                dbc.Row([
                    dbc.Col([
                        dbc.Label(f"Route for {action}"),
                        dropdown
                    ])
                ])
            )
        return inputs
    return []

# Callback to handle saving, updating, and deleting rules
@app.callback(
    Output("rules-container", "children"),
    [Input("save-rule-button", "n_clicks"), Input({'type': 'delete-rule', 'index': dash.dependencies.ALL}, 'n_clicks')],
    [State("rule-name-input", "value"), State({'type': 'parameter-value-dropdown', 'index': dash.dependencies.ALL}, 'value'), State({'type': 'parameter-value-input', 'index': dash.dependencies.ALL}, 'value'), State("action-dropdown", "value"), State({'type': 'action-value-dropdown', 'index': dash.dependencies.ALL}, 'value')]
)
def handle_rule_changes(save_click, delete_clicks, rule_name, selected_parameters, parameter_values, selected_actions, action_values):
    ctx = dash.callback_context

    if not ctx.triggered:
        raise PreventUpdate

    global rules

    if ctx.triggered[0]['prop_id'] == 'save-rule-button.n_clicks' and save_click:
        if not rule_name:
            raise PreventUpdate

        # Create the rule structure
        rule = {
            'name': rule_name,
            'parameters': {},
            'actions': {}
        }

        # Handle parameter values
        for param, value in zip(selected_parameters, parameter_values):
            if isinstance(value, list):
                rule['parameters'][param] = ','.join(value)
            else:
                rule['parameters'][param] = value

        # Handle action values
        for action, value in zip(selected_actions, action_values):
            if isinstance(value, list):
                rule['actions'][action] = ','.join(value)
            else:
                rule['actions'][action] = value

        # Generate card for the new rule
        new_rule_card = dbc.Card(
            dbc.CardBody([
                html.H5(rule_name, className="card-title", id={'type': 'rule-name', 'index': rule_name}),
                html.H6("Parameters", className="card-subtitle"),
                html.Ul([html.Li(f"{k}: {v}") for k, v in rule['parameters'].items()]),
                html.H6("Actions", className="card-subtitle mt-2"),
                html.Ul([html.Li(f"{k}: {v}") for k, v in rule['actions'].items()]),
                dbc.Button("Edit", id={'type': 'edit-rule', 'index': rule_name}, color="warning", className="mr-2"),
                dbc.Button("Delete", id={'type': 'delete-rule', 'index': rule_name}, color="danger")
            ]),
            id=rule_name,
            style={'width': '100%', 'height': 'auto', 'margin': '10px', 'display': 'inline-block', 'verticalAlign': 'top'},
            className="mt-3"
        )

        # Remove existing rule if it exists
        rules = [rule for rule in rules if rule['props']['id'] != rule_name]
        rules.append(new_rule_card)

    elif ctx.triggered[0]['prop_id'].startswith('delete-rule'):
        rule_name_to_delete = ctx.triggered[0]['prop_id'].split('.')[0].split('index": "')[1].split('"')[0]
        rules = [rule for rule in rules if rule['props']['id'] != rule_name_to_delete]

    return rules

# Callback to handle editing of rules
@app.callback(
    [Output("rule-name-input", "value"), Output("parameter-dropdown", "value"), Output("parameter-inputs-container", "children"), Output("action-dropdown", "value"), Output("action-inputs-container", "children")],
    [Input({'type': 'edit-rule', 'index': dash.dependencies.ALL}, 'n_clicks')],
    [State({'type': 'edit-rule', 'index': dash.dependencies.ALL}, 'id')]
)
def handle_edit_rule(edit_clicks, rule_ids):
    ctx = dash.callback_context

    if not ctx.triggered:
        raise PreventUpdate

    rule_id = ctx.triggered[0]['prop_id'].split('.')[0].split('index": "')[1].split('"')[0]
    
    for rule in rules:
        if rule['props']['id'] == rule_id:
            rule_name = rule['props']['id']
            parameters = [param.split(': ')[0] for param in rule['props']['children'][1]['props']['children']]
            actions = [action.split(': ')[0] for action in rule['props']['children'][2]['props']['children']]
            return rule_name, parameters, update_parameter_inputs(parameters), actions, update_action_inputs(actions)
    
    raise PreventUpdate

# Run the app
if __name__ == '__main__':
    app.run_server(debug=True)
