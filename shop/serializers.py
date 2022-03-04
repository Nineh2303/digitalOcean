
from django.db.models import fields
from rest_framework import serializers
from .models import Category, Product
class ProductSerializer(serializers.ModelSerializer): 
    
    class Meta: 
        model = Product 
        fields = ['title','description','slug', 'price','get_product_url','category']

class CategorySerializer(serializers.ModelSerializer): 
    products = ProductSerializer(many=True)
    class Meta: 
        model = Category 
        fields =  ['name', 'slug', 'image', 'get_category_url', 'products']

