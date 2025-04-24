:- use_module(library(http/thread_httpd)).
:- use_module(library(http/http_dispatch)).
:- use_module(library(http/http_parameters)).
:- use_module(library(http/html_write)).
:- use_module(library(http/http_error)).
:- use_module(library(http/html_head)).


:- dynamic transaction/10.

:- [transactions_1000].  % Load from file

% Web server
:- http_handler(root(.), homepage_handler, []).
:- http_handler(root(check_id), check_id_handler, []).
:- http_handler(root(temp_check), temp_check_handler, []).
:- http_handler(root(report), report_handler, []).

start_server(Port) :-
    http_server(http_dispatch, [port(Port)]).

% =======================
% Fraud detection rules
% =======================

high_amount_odd_hour(ID) :-
    transaction(ID, Amount, Hour, _, _, _, _, _, _, _),
    Amount > 500000,
    (Hour < 6 ; Hour > 22).

foreign_highrisk_online(ID) :-
    transaction(ID, _, _, _, _, _, 'online', _, yes, yes).

new_account_mobile(ID) :-
    transaction(ID, Amount, _, _, _, Age, _, 'mobile', _, _),
    Age < 1.0,
    Amount > 300000.

location_mismatch_risky_device(ID) :-
    transaction(ID, _, _, Origin, Destination, _, _, Device, _, _),
    Origin \= Destination,
    member(Device, ['mobile', 'POS']).

atm_suspicious(ID) :-
    transaction(ID, Amount, _, _, _, Age, 'ATM', _, _, _),
    Amount > 250000,
    Age < 2.0.

early_hour(ID) :-
    transaction(ID, _, Hour, _, _, _, _, _, _, _),
    Hour >= 0,
    Hour =< 5.

fraudulent(ID) :-
    high_amount_odd_hour(ID);
    foreign_highrisk_online(ID);
    new_account_mobile(ID);
    location_mismatch_risky_device(ID);
    atm_suspicious(ID);
    early_hour(ID).

% =======================
% UI Handlers
% =======================

homepage_handler(_Request) :-
    reply_html_page(
        [title('Fraud Detection System')],
        [ style(type('text/css'), [
              'body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }',
              '.container { max-width: 800px; margin: auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }',
              '.card { margin-bottom: 30px; padding: 20px; border-left: 5px solid #2196F3; background: #fafafa; border-radius: 8px; }',
              '.card h2 { margin-top: 0; color: #333; }',
              'input[type=text], input[type=number] { width: 100%; padding: 8px; margin-top: 5px; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px; }',
              'input[type=submit] { background-color: #2196F3; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-size: 16px; }',
              'input[type=submit]:hover { background-color: #1976D2; }'
          ]),
          div([class(container)],
              [ h1('Fraud Detection Expert System'),
                div([class(card)],
                    [ h2('1. Check Existing Transaction'),
                      form([action('/check_id'), method('POST')],
                           [ label(for(id), 'Transaction ID:'),
                             input([name(id), type(text), placeholder('e.g. txn101')]),
                             input([type(submit), value('Check Transaction')])
                           ])
                    ]),
                div([class(card)],
                    [ h2('2. Check Temporary Transaction'),
                      form([action('/temp_check'), method('POST')],
                           [ input([name(id), placeholder('Transaction ID')]),
                             input([name(amount), type(number), placeholder('Amount')]),
                             input([name(hour), type(number), placeholder('Hour (0-23)')]),
                             input([name(origin), placeholder('Origin')]),
                             input([name(destination), placeholder('Destination')]),
                             input([name(age), type(number), step(0.1), placeholder('Account Age (years)')]),
                             input([name(channel), placeholder('Channel (ATM/online/etc.)')]),
                             input([name(device), placeholder('Device (mobile/POS/etc.)')]),
                             input([name(risky), placeholder('Risky (yes/no)')]),
                             input([name(foreign), placeholder('Foreign (yes/no)')]),
                             input([type(submit), value('Check Now')])
                           ])
                    ]),
                div([class(card)],
                    [ h2('3. Generate Report'),
                      form([action('/report'), method('GET')],
                           [ input([type(submit), value('Generate Fraud Report')])
                           ])
                    ])
              ])
        ]).

check_id_handler(Request) :-
    http_parameters(Request, [id(ID, [])]),
    (fraudulent(ID) ->
        Message = 'Transaction is potentially fraudulent.';
        Message = 'Transaction appears normal.'),
    reply_html_page(title('Check Result'), [h2(Message), a([href('/')], '← Back')]).

temp_check_handler(Request) :-
    http_parameters(Request,
        [ id(ID, []),
          amount(AmountAtom, []),
          hour(HourAtom, []),
          origin(Origin, []),
          destination(Destination, []),
          age(AgeAtom, []),
          channel(Channel, []),
          device(Device, []),
          risky(RiskyAtom, []),
          foreign(ForeignAtom, [])
        ]),
    atom_number(AmountAtom, Amount),
    atom_number(HourAtom, Hour),
    atom_number(AgeAtom, Age),
    atom_string(RiskyAtom, RiskyStr), (RiskyStr == "yes" -> Risky = yes ; Risky = no),
    atom_string(ForeignAtom, ForeignStr), (ForeignStr == "yes" -> Foreign = yes ; Foreign = no),

    % Check the fraud rules and collect matched rules
    (   (Amount > 500000, (Hour < 6 ; Hour > 22)) ->
        Rule = 'high_amount_odd_hour'
    ;   (Channel = 'online', Risky == yes, Foreign == yes) -> 
        Rule = 'foreign_highrisk_online'
    ;   (Age < 1.0, Amount > 300000, Device = 'mobile') -> 
        Rule = 'new_account_mobile'
    ;   (Origin \= Destination, member(Device, ['mobile', 'POS'])) -> 
        Rule = 'location_mismatch_risky_device'
    ;   (Channel = 'ATM', Amount > 250000, Age < 2.0) -> 
        Rule = 'atm_suspicious'
    ;   (Hour >= 0, Hour =< 5) -> 
        Rule = 'early_hour'
    ;   Rule = 'no_rule_matched'
    ),

    % Prepare the message based on whether a rule is matched
    ( Rule \= 'no_rule_matched' ->
        Message = 'Transaction is fraudulent.',
        MatchedRuleMessage = ['Rule matched: ', Rule]
    ;   Message = 'Transaction is not fraudulent.',
        MatchedRuleMessage = ['No rules matched.']
    ),

    % Reply with the result message and matched rule(s)
    reply_html_page(
        title('Temporary Check Result'),
        [ h3(Message),
          p(MatchedRuleMessage),
          a([href('/')], '← Back')
        ]).

report_handler(_Request) :-
    findall(ID, fraudulent(ID), FraudList),
    maplist(wrap_item, FraudList, HTMLList),
    reply_html_page(title('Fraudulent Transactions'),
                    [ h2('Fraudulent Transaction IDs'),
                      ul(HTMLList),
                      a([href('/')], '← Back')
                    ]).

wrap_item(ID, li(ID)).

