-- Recovery Proof clean-point DB fixture
CREATE TABLE users (id integer, email text);
COPY public.users (id, email) FROM stdin;
1	user1@example.com
2	user2@example.com
3	user3@example.com
4	user4@example.com
5	user5@example.com
6	user6@example.com
7	user7@example.com
8	user8@example.com
9	user9@example.com
10	user10@example.com
\.
CREATE TABLE orders (id integer, user_id integer, total_cents integer);
COPY public.orders (id, user_id, total_cents) FROM stdin;
1	2	1007
2	3	1014
3	4	1021
4	5	1028
5	6	1035
6	7	1042
7	8	1049
8	9	1056
9	10	1063
10	1	1070
11	2	1077
12	3	1084
13	4	1091
14	5	1098
15	6	1105
16	7	1112
17	8	1119
18	9	1126
19	10	1133
20	1	1140
\.
