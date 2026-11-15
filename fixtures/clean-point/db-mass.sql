-- Recovery Proof clean-point DB fixture
CREATE TABLE users (id integer, email text);
COPY public.users (id, email) FROM stdin;
1	user1@other.com
2	user2@other.com
3	user3@other.com
4	user4@other.com
5	user5@other.com
6	user6@other.com
7	user7@other.com
8	user8@other.com
9	user9@example.com
10	user10@example.com
\.
CREATE TABLE orders (id integer, user_id integer, total_cents integer);
COPY public.orders (id, user_id, total_cents) FROM stdin;
1	2	9999
2	3	9999
3	4	9999
4	5	9999
5	6	9999
6	7	9999
7	8	9999
8	9	9999
9	10	9999
10	1	9999
11	2	9999
12	3	9999
13	4	9999
14	5	9999
15	6	9999
16	7	1112
17	8	1119
18	9	1126
19	10	1133
20	1	1140
\.
