#!/usr/bin/env python3

from flask import request, session, jsonify, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        
        try:
            
            if not data.get('username'):
                raise ValueError("Username is required")
            if not data.get('password'):
                raise ValueError("Password is required")
                
            new_user = User(
                username=data['username'],
                image_url=data.get('image_url'),
                bio=data.get('bio')
            )
            
            new_user.password_hash = data['password']
            
            db.session.add(new_user)
            db.session.commit()
            
            session['user_id'] = new_user.id
            
            return make_response(
                jsonify({
                    'id': new_user.id,
                    'username': new_user.username,
                    'image_url': new_user.image_url,
                    'bio': new_user.bio
                }), 
                201
            )
        
        except (ValueError, IntegrityError) as e:
            db.session.rollback()
            return make_response(
                jsonify({'errors': [str(e)]}),
                422
            )

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_response(
                jsonify({'error': 'Unauthorized'}),
                401
            )
        
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return make_response(
                jsonify({'error': 'User not found'}),
                401
            )
        
        return make_response(
            jsonify({
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }),
            200
        )

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return make_response(
                jsonify({
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }),
                200
            )
        else:
            return make_response(
                jsonify({'error': 'Invalid username or password'}),
                401
            )

class Logout(Resource):
    def delete(self):
        if 'user_id' in session:
            session.pop('user_id')
            return make_response('', 401)  
        else:
            return make_response(
                jsonify({'error': 'Not logged in'}),
                401
            )

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_response(
                jsonify({'error': 'Unauthorized'}),
                401
            )
        
        
        user = User.query.get(user_id)
        if not user:
            session.pop('user_id', None)
            return make_response(
                jsonify({'error': 'Unauthorized'}),
                401
            )
        
        recipes = Recipe.query.all()
        recipes_data = [{
            'id': recipe.id,
            'title': recipe.title,
            'instructions': recipe.instructions,
            'minutes_to_complete': recipe.minutes_to_complete,
            'user': {
                'id': recipe.user.id,
                'username': recipe.user.username,
                'image_url': recipe.user.image_url,
                'bio': recipe.user.bio
            }
        } for recipe in recipes]
        
        return make_response(jsonify(recipes_data), 200)

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_response(
                jsonify({'error': 'Unauthorized'}),
                401
            )
        
        
        user = User.query.get(user_id)
        if not user:
            session.pop('user_id', None)
            return make_response(
                jsonify({'error': 'Unauthorized'}),
                401
            )
        
        data = request.get_json()
        
        try:
            new_recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data.get('minutes_to_complete'),
                user_id=user.id
            )
            
            db.session.add(new_recipe)
            db.session.commit()
            
            response_data = {
                'id': new_recipe.id,
                'title': new_recipe.title,
                'instructions': new_recipe.instructions,
                'minutes_to_complete': new_recipe.minutes_to_complete,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }
            }
            
            return make_response(jsonify(response_data), 201)
        
        except ValueError as e:
            db.session.rollback()
            return make_response(
                jsonify({'errors': [str(e)]}),
                422
            )

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)