import re
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from  rest_framework import serializers, status, viewsets

from shop.models import Product
from shop.serializers import ProductSerializer
from .models import Cart, Item, Order

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from .generateId import  getRandomCartId, getRandomItemId

from .serializers import CartSerializer, ItemSerializer, OrderSerializer
# Create your views here.
class CartView(APIView):
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated,)
    def get(self, request): 
        user= request.user 
        cart= Cart.objects.filter(user = user, ordered= False).first()
        if(cart is None) : 
            newCart = Cart.objects.create(cartId = getRandomCartId(), user =user)
            newCart.save() 
            serializer = CartSerializer(newCart)
            return Response({"Cart" : serializer.data}, status = status.HTTP_200_OK)
        serializer = CartSerializer(cart)
        return Response({"Cart" : serializer.data}, status = status.HTTP_200_OK)

class getItemsView(APIView):
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated,)
    def get(self, request):
        user = request.user 
        cart= Cart.objects.get(user = user, ordered= False)
        item = Item.objects.filter(cart= cart) 
        serializer= ItemSerializer(item, many = True) 
        for item in serializer.data :
            product =  ProductSerializer(Product.objects.get(id=item['product'])).data
            item['product'] = product

        return Response({"listItem":serializer.data},status = status.HTTP_200_OK)


class addToCart(APIView): 
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated,)
    def post(self,request):
        
        user= request.user 
        cart= Cart.objects.filter(user = user, ordered= False).first()
        product = request.data['product']
        quantity = request.data['quantity']
        query = Product.objects.get(title=product['title'])
        try:
            item = Item.objects.get(cart=cart , product = query)
            if (item):
                item.quantity =  quantity 
                item.getTotal()
                cart.update()
                return Response({"msg": "Update Success"}, status=status.HTTP_200_OK)
        except:
            newItem = {
                "cart": cart.id,
                "product" : query.id,
                "quantity" :quantity
                
            }
            serializer =ItemSerializer(data=newItem)
            if(serializer.is_valid()):
                item = Item.objects.create(cart= cart, itemKey = getRandomItemId(cart.id) ,product = query , quantity= quantity)
                try :
                    item.getTotal()
                    cart.update()
                    return Response({"msg": "Add succeess"}, status=status.HTTP_200_OK)
                except Exception as e: 
                    print(e.message)
                    return Response({"msg": "Something went wrong", "status":400}, status=status.HTTP_200_OK)
            else:
                print(serializer.errors)
        
        return Response({"msg": "succeess"}, status=status.HTTP_200_OK)


class removeItem(APIView):
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated,)
    def post(self, request): 
        user = request.user 
        itemKey = request.data['itemKey']
        try : 
            item = Item.objects.get(itemKey = itemKey) 
            print (item)
            item.delete()
            
            cart= Cart.objects.filter(user = user, ordered= False).first()
            cart.update()
            return Response({"msg":"Delete item success"}, status=status.HTTP_200_OK)
        except Exception  as e: 
            print (e)
            return Response({"msg":"Something went Wrong"}, status=status.HTTP_404_NOT_FOUND)
        

class orderView(APIView): 
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated,)
    def post(self, request):
        user= request.user
        data = request.data
        try : 
            cart = Cart.objects.get(cartId= data["cart"])
            data["cart"] = cart 
            order = Order.objects.create(user = user,**data) 
            order.save()
            cart.setOrdered()
        except Exception as e : 
            print(e)
            return Response ({"msg" : "Some thing went wrong, please try again !!! "} , status = status.HTTP_400_BAD_REQUEST)
        return Response({"msg":"Order Success, back to homepage !!"}, status=status.HTTP_200_OK)


class getOrderListView(APIView): 
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated,)
    def get(self,request): 
        user = request.user 
        cartList = Cart.objects.filter(user= user, ordered=True)
        serializer = CartSerializer(cartList, many=True)
        data = serializer.data 
        for order in data : 
            for item in order['items']: 
                item['product'] =   ProductSerializer(Product.objects.get(pk=item['product'])).data
        return Response({"OrderList": serializer.data}, status=status.HTTP_200_OK)


class getItemInCartView(APIView): 
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated,)
    def post(self, request):
        user= request.user
        item = Item.objects.filter(cart=Cart.objects.get(cartId = request.data['cart']))
        serializer = ItemSerializer(item, many = True )
        return Response({"listItem " : serializer.data}, status=status.HTTP_200_OK)

