# IMHOweb
Web, Domain and email hosting

## To create the initial db and manual user add

source venv/bin/activate
python

.. code-block:: python

    from app import User, db
    from werkzeug.security import generate_password_hash, check_password_hash

    db.drop_all() # Drops all the db
    db.create_all() # Create tables using the db model
    u1 = User(email="user@domain.com", fname="Aye Barry", bio="Une Femme Medicine")
    db.session.add(u1)

    plain_password = "qwerty"
    hashed_password = generate_password_hash(plain_password)
    print(hashed_password)

    u1 = User(password=hashed_password)
    db.session.add(u1)
    db.session.commit()

    User.query.all()

## Running
venv
python app.py 


Installing
------------

Pull the Git repo

.. code-block:: text

    $ git clone imhoweb.git 
    $ cd imhoweb
    $ python3 -m venv venv


Install and update using `pip`_:

.. code-block:: text

    $ . venv/bin/activate
    $ (venv) pip install -r requirements
    $ pip install --editable .


A Simple Example
----------------

.. code-block:: text

    $ python app.py
     * Serving Flask app "IMHOweb"
     * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)


Links
-----

* Website: https://www.imhoweb.net
* Issue Tracker: https://github.com/imhodot/IMHOweb/issues
* Test status:

  * Linux, Mac: https://travis-ci.org/uobis/imhoweb

* Test coverage: https://codecov.io/gh/uobis/imhoweb
