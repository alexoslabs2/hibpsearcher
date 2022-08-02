# hibpsearcher
Search information about where credential was leaked in Have I Been Pwned's database

Usage:

* Create a file containing the email(s) 

vim emails.txt

        user1@example.com

        user2@example.com

        user3@example.com

* Run the script

python3 hibp.py emails.txt

      user1@example.com

      Cit0day ['Email addresses', 'Passwords']

      user2@example.com

      Canva ['Email addresses', 'Geographic locations', 'Names', 'Passwords', 'Usernames']

      user3@example.com

      Cit0day ['Email addresses', 'Passwords']
