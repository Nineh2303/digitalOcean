from rest_framework import fields, serializers
from .models import Cart , Item, Order
from shop.serializers import ProductSerializer


class ItemSerializer(serializers.ModelSerializer):
    class Meta: 
        model = Item
        fields = ["cart",'quantity','itemKey','totalPrice', 'product']
    





        
class OrderSerializer(serializers.ModelSerializer): 
    class Meta: 
        model = Order 
        fields = ("id","name","address","numberPhone","shipped")

class CartSerializer(serializers.ModelSerializer): 
    order = OrderSerializer(many=True, read_only=True)
    items = ItemSerializer(many=True)
    class Meta : 
        model =  Cart 
        fields = ['cartId', 'user', 'count', 'totalCart', 'items', "order"]


        