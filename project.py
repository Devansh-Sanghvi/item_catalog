import string
import random
import json
import requests
import httplib2
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
from flask import make_response
from flask import session as login_session
from database_setup import Base, Category, Item, User
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, asc
from flask import (Flask,
                   render_template,
                   request,
                   redirect,
                   jsonify,
                   url_for,
                   flash)

app = Flask(__name__)

#
CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())[
    'web']['client_id']

# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db', connect_args={
    'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/login')
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token

    url = str(
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
        access_token)

    h = httplib2.Http()

    result = json.loads(h.request(url, 'GET')[1].decode())
    print(url)
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    print(data)
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    print(access_token)
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # NOQA
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['user_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps(
                'Failed to revoke token for given user.',
                400))
        response.headers['Content-Type'] = 'application/json'
        return response


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except BaseException:
        return None


@app.route('/categories')
def categories():
    categories = session.query(Category).all()
    if 'username' not in login_session:
        return render_template('publicCategories.html', categories=categories)
    else:
        return render_template('categories.html', categories=categories)


@app.route('/categories/addCategory/', methods=['POST', 'GET'])
def addCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        category = Category(
            name=request.form['category'],
            user_id=login_session['user_id'])
        session.add(category)
        session.commit()
        flash("Added Category")
        return redirect(url_for('categories'))
    if request.method == 'GET':
        return render_template('newCategory.html')


@app.route(
    '/categories/editCategory/<int:category_id>/',
    methods=[
        'POST',
        'GET'])
def editCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        category = session.query(
            Category).filter_by(id=category_id).one()
        if category.user_id != login_session['user_id']:
            return """<script>function myFunction() {
                      alert('You are not authorized to edit this category ');}
                      </script><body onload='myFunction()'>"""
        if request.form['category'] != '':
            category.name = request.form['category']
            session.add(category)
            session.commit()
            flash("edited category")
            return redirect(url_for('categories'))

    elif request.method == 'GET':
        category = session.query(
            Category).filter_by(id=category_id).one()
        return render_template('editCategory.html', category=category)


@app.route(
    '/categories/deleteCategory/<int:category_id>',
    methods=[
        'POST',
        'GET'])
def deleteCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        category = session.query(
            Category).filter_by(id=category_id).one()
        if category.user_id != login_session['user_id']:
            return """<script>function myFunction() {
                      alert('You are not authorized to edit this category ');}
                      </script><body onload='myFunction()'>"""
        session.delete(category)
        session.commit()
        flash('category  deleted')
        return redirect(url_for('categories'))

    elif request.method == 'GET':
        category = session.query(
            Category).filter_by(id=category_id).one()
        return render_template('deleteCategory.html', category=category)


@app.route('/categories/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(
        categories=[
            category.serialize for category in categories])


@app.route('/categories/<int:category_id>/')
def items(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    items = session.query(Item).filter_by(category_id=category_id)
    if category.user_id != login_session['user_id']:
        return render_template(
            'publicItems.html',
            category=category,
            items=items)

    return render_template('items.html', category=category, items=items)


@app.route('/categories/<int:category_id>/<int:item_id>/JSON')
def itemJSON(category_id, item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Items=[item.serialize])


@app.route('/categories/<int:category_id>/JSON')
def itemsJSON(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/category/<int:category_id>/new/', methods=['GET', 'POST'])
def newItem(category_id):

    if request.method == 'POST':
        category = session.query(
            Category).filter_by(id=category_id).one()
        if category.user_id != login_session['user_id']:
            return """<script>function myFunction() {
                      alert('You are not authorized to edit this category ');}
                      </script><body onload='myFunction()'>"""
        if request.form['name'] != '' and request.form['description'] != '':
            new_item = Item(
                name=request.form['name'],
                description=request.form['description'],
                category_id=category_id)
            session.add(new_item)
            session.commit()
            flash("new item added")
            return redirect(
                url_for(
                    'items',
                    category_id=category_id))

    elif request.method == 'GET':
        category = session.query(
            Category).filter_by(id=category_id).one()
        return render_template('newItem.html', category=category)


# Task 2: Create route for editMenuItem function here

@app.route(
    '/categories/<int:category_id>/<int:item_id>/edit/',
    methods=[
        'GET',
        'POST'])
def editItem(category_id, item_id):

    if request.method == 'POST':
        category = session.query(
            Category).filter_by(id=category_id).one()
        item = session.query(Item).filter_by(id=item_id).one()
        if category.user_id != login_session['user_id']:
            return """<script>function myFunction() {
                      alert('You are not authorized to edit this category ');}
                      </script><body onload='myFunction()'>"""
        if request.form['name'] != '':
            item.name = request.form['name']

        if request.form['description'] != '':
            item.description = request.form['description']

        session.add(item)
        session.commit()
        flash("edited item")
        return redirect(url_for('items', category_id=category_id))
    elif request.method == 'GET':
        category = session.query(
            Category).filter_by(id=category_id).one()
        item = session.query(Item).filter_by(id=item_id).one()
        return render_template(
            'editItem.html',
            category=category,
            item=item)


# Task 3: Create a route for deleteMenuItem function here

@app.route(
    '/categories/<int:category_id>/<int:item_id>/delete/',
    methods=[
        'GET',
        'POST'])
def deleteItem(category_id, item_id):
    if request.method == 'POST':
        print('jdndsfdsj')
        category = session.query(
            Category).filter_by(id=category_id).one()
        if category.user_id != login_session['user_id']:
            return """<script>function myFunction() {
                      alert('You are not authorized to edit this category ');}
                      </script><body onload='myFunction()'>"""
        item = session.query(Item).filter_by(id=item_id).one()
        session.delete(item)
        session.commit()
        flash("deleted item")
        items = session.query(Item).all()

        if len(items) < 1:
            return redirect('/categories')
        return redirect(
            url_for(
                'items',
                category_id=item.category_id))
    elif request.method == 'GET':
        item = session.query(Item).filter_by(id=item_id).one()
        return render_template('deleteItem.html', item=item)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
