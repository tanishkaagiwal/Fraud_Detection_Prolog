:- [transactions_1000].  % Make sure this file is in the same folder

% Rule 1: High amount during odd hours
high_amount_odd_hour(ID) :-
    transaction(ID, Amount, Hour, _, _, _, _, _, _, _),
    Amount > 500000,
    (Hour < 6 ; Hour > 22).

% Rule 2: Foreign & high-risk transaction over online channel
foreign_highrisk_online(ID) :-
    transaction(ID, _, _, _, _, _, 'online', _, yes, yes).

% Rule 3: New account, large amount, mobile device
new_account_mobile(ID) :-
    transaction(ID, Amount, _, _, _, Age, _, 'mobile', _, _),
    Age < 1.0,
    Amount > 300000.

% Rule 4: Origin and destination mismatch with risky device
location_mismatch_risky_device(ID) :-
    transaction(ID, _, _, Origin, Destination, _, _, Device, _, _),
    Origin \= Destination,
    member(Device, ['mobile', 'POS']).

% Rule 5: Transactions through ATM with high amount and low account age
atm_suspicious(ID) :-
    transaction(ID, Amount, _, _, _, Age, 'ATM', _, _, _),
    Amount > 250000,
    Age < 2.0.

% Rule 6: Rapid transactions in early hours (simulate pattern detection)
early_hour(ID) :-
    transaction(ID, _, Hour, _, _, _, _, _, _, _),
    Hour >= 0,
    Hour =< 5.

% Final fraud rule: any of the above trigger flags
fraudulent(ID) :-
    high_amount_odd_hour(ID);
    foreign_highrisk_online(ID);
    new_account_mobile(ID);
    location_mismatch_risky_device(ID);
    atm_suspicious(ID);
    early_hour(ID).

% Print a list of IDs
print_list([]).
print_list([H|T]) :-
    write('- '), write(H), nl,
    print_list(T).

% Generate a report of all fraudulent transactions
generate_report :-
    findall(ID, fraudulent(ID), List),
    write('Suspicious Transactions:'), nl,
    print_list(List).
% cmd : generate_report.

% run a query to check if transaction is fraudulent or not
check_fraud(ID) :-
    (fraudulent(ID) ->
        write(' Transaction is potentially fraudulent.');
        write(' Transaction appears normal.')).

% cmd : check_fraud(tx3)

check_temp_transaction(ID, Amount, Hour, Origin, Destination, Age, Channel, Device, Risky, Foreign) :-
    (   (Amount > 500000, (Hour < 6 ; Hour > 22)) ->
        write('Rule matched: high_amount_odd_hour'), nl
    ;   (Channel = 'online', Risky = yes, Foreign = yes) ->
        write('Rule matched: foreign_highrisk_online'), nl
    ;   (Age < 1.0, Amount > 300000, Device = 'mobile') ->
        write('Rule matched: new_account_mobile'), nl
    ;   (Origin \= Destination, member(Device, ['mobile', 'POS'])) ->
        write('Rule matched: location_mismatch_risky_device'), nl
    ;   (Channel = 'ATM', Amount > 250000, Age < 2.0) ->
        write('Rule matched: atm_suspicious'), nl
    ;   (Hour >= 0, Hour =< 5) ->
        write('Rule matched: early_hour'), nl
    ;   write('✅ No fraud rule triggered.'), nl
    ).
    