from flask import Flask, redirect, request, jsonify, render_template, make_response
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, JWTManager,\
get_jwt_identity, get_jwt, unset_jwt_cookies
import requests
import uuid
import random
from datetime import datetime, timedelta, timezone
from hashlib import sha1, sha256
from base64 import urlsafe_b64encode, b64encode
from DataBase import SQLighter

base = SQLighter('sqldatabase.db')
app = Flask(__name__)
jwt = JWTManager(app)

app.config['SECRET_KEY'] = ''

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
global_salt = ''
domen = ''
xlist = ['registration', 'loginrest', 'loginrest_cookie', 'logout', 'logout_refresh', 'shorter', 'public_shorter',
         'reg', 'pvt', 'acc', 'prt', 'refresh', 'leave', 'account', 'join', 'login', 'delete_links', 'get_links']

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = base.jti_exists(jti)
    return token is not None
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/registration', methods=['POST'])
def create_user():
    if request.method == 'POST':
        data = request.get_json()
        login = data['login']
        email = data['email']
        if (not base.email_exist(email)):
            password = data['password']
            if (not base.user_exist(login)):
                admin = False
                salt = uuid.uuid4().hex
                for i in range (10):
                    hashed_password = b64encode(sha256(str(global_salt + password + salt).encode()).digest()).decode()
                    password = hashed_password
                base.add_user(login, email, password, salt, admin)
                return jsonify({'message': 'success'})
            else:
                return jsonify({'message': 'Недопустимое имя пользователя'})
        else:
            return jsonify({'message': 'Email уже использовался'})

@app.route('/loginrest', methods=['POST'])
def loginrest():
    if request.method == 'POST':
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify', 401, {'message': 'no data'})
        login = auth.username
        password = auth.password
        user = base.get_one_user(login)
        if not user:
            return jsonify({'message': 'Такого пользователя не существует'})
        password_hash = base.get_password_hash(login)
        data = password
        for i in range (10):
            check = b64encode(sha256(str(global_salt + data + password_hash[1]).encode()).digest()).decode()
            data = check
        if data == password_hash[0]:
            access_token = create_access_token(identity=login)
            refresh_token = create_refresh_token(identity=login)
            resp = jsonify({'message' : 'success','Login': '{}'.format(login),
                'access_token': access_token,
                'refresh_token': refresh_token})
            return resp
        return jsonify({'message': 'Неверный пароль'})

@app.route('/loginrest_cookie', methods=['POST'])
def loginrest_cookie():
    if request.method == 'POST':
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify', 401, {'message': 'no data'})
        login = auth.username
        password = auth.password
        answer = requests.post(domen + 'loginrest', auth=(login, password))
        if (answer.json())['message'] == 'success':
            resp = make_response({'message': 'succes, cookie set'})
            resp.set_cookie('access_token_cookie', (answer.json())['access_token'])
            resp.set_cookie('refresh_token_cookie', (answer.json())['refresh_token'])
            return resp
        else:
            return jsonify({'message': 'error'})

@app.route("/logout", methods=["DELETE"])
@jwt_required()
def modify_token():
    if request.method == 'DELETE':
        jti = get_jwt()["jti"]
        now = datetime.now(timezone.utc)
        base.add_jti(jti, now)
        return jsonify(msg="JWT revoked")

@app.route("/logout_refresh", methods=["DELETE"])
@jwt_required(refresh=True)
def modify_refresh_token():
    if request.method == 'DELETE':
        jti = get_jwt()["jti"]
        now = datetime.now(timezone.utc)
        base.add_jti(jti, now)
        response = jsonify(msg="JWT revoked")
        unset_jwt_cookies(response)
        return response

@app.route('/shorter', methods=['POST'])
@jwt_required()
def add_url():
    if request.method == 'POST':
        current_user = get_jwt_identity()
        data = request.get_json()
        alias = (data['alias'])
        link = data['linked']
        type_url = data['type']
        if link[:7] != 'https:/' and link[:6] != 'http:/':
            link = 'http://'+link
        if (not base.url_exists(link, current_user)):
            url_len = random.randrange(8, 13)
            salt = uuid.uuid4().hex
            short_url = urlsafe_b64encode(sha1(str(link + salt).encode()).digest()).decode()[0:url_len]
            if len(data['alias']) != 0:
                if data['alias'] in xlist:
                    return jsonify({'message': 'Алиас занят'})
                if (not base.short_url_exists(alias)):
                    short_url = data['alias']
                else:
                    return jsonify({'message': 'Алиас занят'})
            if (not base.short_url_exists(short_url)):
                base.add_url(link, short_url, type_url, current_user)
                short_link = base.get_short_url(link, current_user)[0]
                return jsonify({'short_link' : domen + short_link, 'message': 'access'})
        else:
            if len(data['alias']) != 0:
                if data['alias'] in xlist:
                    return jsonify({'message': 'Алиас занят'})
                if (not base.short_url_exists(alias)):
                    short_url = data['alias']
                else:
                    return jsonify({'message': 'Алиас занят'})
                base.update_url_with_alias(type_url, short_url, link, current_user)
                short_link = base.get_short_url(link, current_user)[0]
                return jsonify({'short_link': domen + short_link, 'message': 'access'})
            else:
                base.update_url(type_url, link, current_user)
                short_link = base.get_short_url(link, current_user)[0]
                return jsonify({'short_link' : domen + short_link, 'message': 'access'})

@app.route('/public_shorter', methods=['POST'])
def add_url_public():
    if request.method == 'POST':
        current_user = 'public%'
        data = request.get_json()
        alias = (data['alias'])
        link = data['linked']
        type_url = 'public'
        if link[:7] != 'https:/' and link[:6] != 'http:/':
            link = 'http://' + link
        if (not base.url_exists(link, current_user)):
            url_len = random.randrange(8, 13)
            salt = uuid.uuid4().hex
            short_url = urlsafe_b64encode(sha1(str(link + salt).encode()).digest()).decode()[0:url_len]
            if len(data['alias']) != 0:
                if data['alias'] in xlist:
                    return jsonify({'message': 'Алиас занят'})
                if (not base.short_url_exists(alias)):
                    short_url = data['alias']
                else:
                    return jsonify({'message': 'Алиас занят'})
            if (not base.short_url_exists(short_url)):
                base.add_url(link, short_url, type_url, current_user)
                short_link = base.get_short_url(link, current_user)[0]
                return jsonify({'short_link': domen + short_link, 'message': 'access'})
        else:
            if len(data['alias']) != 0:
                if data['alias'] in xlist:
                    return jsonify({'message': 'Алиас занят'})
                if (not base.short_url_exists(alias)):
                    short_url = data['alias']
                else:
                    return jsonify({'message': 'Алиас занят'})
                base.add_url(link, short_url, type_url, current_user)
                return jsonify({'short_link': domen + short_url, 'message': 'access'})
            else:
                short_link = base.get_short_url(link, current_user)[0]
                return jsonify({'short_link': domen + short_link, 'message': 'access'})

@app.route('/acc', methods=['POST'])
@jwt_required()
def acc():
    if request.method == 'POST':
        current_user = get_jwt_identity()
        links = base.get_all_links(current_user)
        output = []
        for i in range (len(links)):
            link = links[i]
            user_data = {}
            user_data['short_url'] = link[0]
            user_data['original_url'] = link[1]
            user_data['type_url'] = link[2]
            user_data['count'] = link[3]
            output.append(user_data)
        return jsonify({'links' : output, 'msg' : 'access'})

@app.route('/delete_links/<link>', methods=['DELETE'])
def delete_links(link):
    if request.method == 'DELETE':
        if (not base.short_url_exists(link)):
            return jsonify({'msg' : 'link_isnt_exist'})
        else:
            base.delete_link(link)
            return jsonify({'msg': 'successfully_delete'})

@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    if request.method == 'POST':
        identity = get_jwt_identity()
        access_token = create_access_token(identity=identity)
        return jsonify(access_token=access_token)

@app.route('/prt', methods=['POST'])
@jwt_required()
def protect():
    if request.method == 'POST':
        current_user = get_jwt_identity()
        return jsonify({"msg" : "access", "user": current_user})

@app.route('/<short_url>', methods=['GET'])
def redirect_public(short_url):
    if request.method == 'GET':
        if (not base.short_url_exists(short_url.strip())):
            return render_template('404.html'), 404
        else:
            type_url = base.get_type(short_url.strip())
            if type_url[0] == 'public':
                original_link = base.get_original_url(short_url.strip())[0]
                count = (base.get_count(short_url))[0]
                base.set_count(count + 1, short_url)
                return redirect(original_link, code=302)
            else:
                if type_url[0] == 'register':
                    c = request.cookies.get('access_token_cookie')
                    seq = requests.post(domen + 'prt', cookies={'access_token_cookie': c})
                    if ((seq.json())['msg']) == 'access':
                        return redirect(domen + 'reg/' + short_url, code=302)
                    if ((seq.json())['msg']) == 'Token has expired':
                        c = request.cookies.get('refresh_token_cookie')
                        seq = requests.post(domen + 'refresh', cookies={'refresh_token_cookie': c})
                        resp = make_response(redirect(domen + 'reg/' + short_url, code=302))
                        resp.set_cookie('access_token_cookie', (seq.json()['access_token']))
                        return resp
                    else:
                        return redirect(domen + 'login', code=302)
                if type_url[0] == 'private':
                    c = request.cookies.get('access_token_cookie')
                    seq = requests.post(domen + 'prt', cookies={'access_token_cookie': c})
                    if ((seq.json())['msg']) == 'access':
                        return redirect(domen + 'pvt/' + short_url, code=302)
                    if ((seq.json())['msg']) == 'Token has expired':
                        c = request.cookies.get('refresh_token_cookie')
                        seq = requests.post(domen + 'refresh', cookies={'refresh_token_cookie': c})
                        resp = make_response(redirect(domen + 'reg/' + short_url, code=302))
                        resp.set_cookie('access_token_cookie', (seq.json()['access_token']))
                        return resp
                    else:
                        return render_template('404.html'), 404

@app.route('/reg/<short_url>', methods=['GET'])
@jwt_required()
def redirect_reg(short_url):
    if request.method == 'GET':
        original_link = base.get_original_url(short_url.strip())[0]
        count = (base.get_count(short_url))[0]
        base.set_count(count + 1, short_url)
        return redirect(original_link, code=302)

@app.route('/pvt/<short_url>', methods=['GET'])
@jwt_required()
def redirect_pvt(short_url):
    if request.method == 'GET':
        current_user = get_jwt_identity()
        user_url = base.get_user_url(short_url.strip())
        if current_user == user_url[0]:
            original_link = base.get_original_url(short_url.strip())[0]
            count = (base.get_count(short_url))[0]
            base.set_count(count + 1, short_url)
            return redirect(original_link, code=302)
        else:
            return render_template('404.html'), 404

#FRONT

@app.route('/account', methods=['GET'])
def account():
    if request.method == 'GET':
        return render_template('account.html')

@app.route('/get_links', methods=['GET'])
def get_links():
    if request.method == 'GET':
        c = request.cookies.get('access_token_cookie')
        answ = requests.post(domen + 'acc', cookies={'access_token_cookie': c})
        if ((answ.json())['msg']) == 'Token has expired':
            c = request.cookies.get('refresh_token_cookie')
            seq = requests.post(domen + 'refresh', cookies={'refresh_token_cookie': c})
            resp = make_response(redirect(domen + 'account'))
            resp.set_cookie('access_token_cookie', (seq.json()['access_token']))
            return resp
        if ((answ.json())['msg']) == 'access':
            return (answ.json())

        else:
            return render_template('404.html'), 404

@app.route('/', methods=['GET','POST'])
def short():
    if request.method == 'GET':
        c = request.cookies.get('access_token_cookie')
        seq = requests.post(domen + 'prt', cookies={'access_token_cookie':c})
        if ((seq.json())['msg']) == 'access':
            return render_template('short.html', res2='account', res3='Мои ссылки', res4='leave', res5='Выход', res6='3')
        if ((seq.json())['msg']) == 'Token has expired':
            c = request.cookies.get('refresh_token_cookie')
            seq = requests.post(domen + 'refresh', cookies={'refresh_token_cookie': c})
            resp = make_response(redirect(domen))
            resp.set_cookie('access_token_cookie', (seq.json()['access_token']))
            return resp
        else:
            return render_template('short.html', res2='login', res3='Вход', res4='join', res5='Регистрация', res6='10')
    if request.method == 'POST':
        c = request.cookies.get('access_token_cookie')
        seq = requests.post(domen + '/prt', cookies={'access_token_cookie': c})
        if ((seq.json())['msg']) == 'access':
            a = str(request.form.get('originallink'))
            b = str(request.form.get('alias'))
            c = request.cookies.get('access_token_cookie')
            access = request.form['acces']
            message = 'Ваша ссылка на: ' + a
            if access == 'public':
                message = 'Ваша публичная ссылка на: ' + a
            if access == 'register':
                message = 'Ваша ссылка для пользователей на: ' + a
            if access == 'private':
                message = 'Ваша приватная ссылка на: ' + a
            if request.form['short'] == 'shorting':
                data1 = {"linked": a, "type": access, 'alias': b}
                seq = requests.post(domen + 'shorter', json=data1, cookies={'access_token_cookie': c})
                if (seq.json())['message'] == 'access':
                    res = (seq.json())['short_link']
                    return render_template('short.html', res=res, res2='account', res3='Мои ссылки', res4='leave', res5='Выход', res6='3', message=message)
                else:
                    message = (seq.json())['message']
                    return render_template('short.html', res2='account', res3='Мои ссылки', res4='leave', res5='Выход', res6='3', message=message)
        if ((seq.json())['msg']) == 'Token has expired':
            c = request.cookies.get('refresh_token_cookie')
            seq = requests.post(domen + 'refresh', cookies={'refresh_token_cookie': c})
            resp = make_response(redirect(domen))
            resp.set_cookie('access_token_cookie', (seq.json()['access_token']))
            return resp
        else:
            a = str(request.form.get('originallink'))
            b = str(request.form.get('alias'))
            access = request.form['acces']
            message = 'Ваша ссылка на: ' + a
            if access == 'public':
                message = 'Ваша публичная ссылка на: ' + a
            if access == 'register':
                message = 'Войдите или зарегистрируйтесь для создания ссылки для пользователей'
                return render_template('short.html', res2='login', res3='Вход', res4='join', res5='Регистрация', res6='10', message=message)
            if access == 'private':
                message = 'Войдите или зарегистрируйтесь для создания приватной ссылки'
                return render_template('short.html', res2='login', res3='Вход', res4='join', res5='Регистрация', res6='10', message=message)
            if request.form['short'] == 'shorting':
                data1 = {"linked": a, 'alias': b}
                seq = requests.post(domen + 'public_shorter', json=data1)
                if (seq.json())['message'] == 'access':
                    res = (seq.json())['short_link']
                    return render_template('short.html', res=res, res2='login', res3='Вход', res4='join', res5='Регистрация', res6='10', message=message)
                else:
                    message = (seq.json())['message']
                    return render_template('short.html', res2='login', res3='Вход', res4='join', res5='Регистрация', res6='10', message=message)

@app.route('/join', methods=['GET','POST'])
def getjoin():
    if request.method == 'GET':
        return render_template('join.html')
    if request.method == 'POST':
        a = str(request.form.get('name'))
        b = str(request.form.get('mail'))
        c = str(request.form.get('up'))
        if request.form['reg'] == 'registration':
            data = {'login': a, 'email': b, 'password': c}
            answer = requests.post(domen + 'registration', json=data)
            if (answer.json())['message'] == 'success':
                return redirect(domen + 'login', code=302)
            else:
                return render_template('join.html', res=(answer.json())['message'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    if request.method == 'POST':
        if request.form['enter'] == 'entered':
            login = str(request.form.get('name'))
            password = str(request.form.get('password'))
            answer = requests.post(domen + 'loginrest', auth=(login, password))
            if (answer.json())['message'] == 'success':
                resp = make_response(redirect('/'))
                resp.set_cookie('access_token_cookie', (answer.json())['access_token'])
                resp.set_cookie('refresh_token_cookie', (answer.json())['refresh_token'])
                return (resp)
            else:
                return render_template('login.html', res=(answer.json())['message'])

@app.route('/leave', methods=['GET'])
def leave():
    if request.method == 'GET':
        c = request.cookies.get('access_token_cookie')
        b = request.cookies.get('refresh_token_cookie')
        requests.delete(domen + 'logout', cookies={'access_token_cookie': c, 'refresh_token_cookie': b})
        requests.delete(domen + 'logout_refresh', cookies={'access_token_cookie': c, 'refresh_token_cookie': b})
        return redirect(domen, code=302)

if __name__ == '__main__':
    app.run()