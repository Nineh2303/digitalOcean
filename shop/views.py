from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import Category, Product
from .serializers import CategorySerializer, ProductSerializer
# Create your views here.


@api_view(['GET'])
def getAllCategories(request):
    categories = Category.objects.all()
    serializer =  CategorySerializer(categories, many = True)
    return Response(serializer.data)
    
@api_view(['GET'])
def getProducts(request, category_slug):
    if (category_slug=='all') :
        products = Product.objects.all()
        serializer =  ProductSerializer(products, many = True)
        return Response(serializer.data)

    category = Category.objects.get(slug=category_slug)
    products = Product.objects.filter(category=category.id)
    serializer =  ProductSerializer(products, many = True)
    return Response(serializer.data)


@api_view(['GET'])
def getSingleProduct(request, product_slug):
    product=  Product.objects.get(slug=product_slug)
    serializer =  ProductSerializer(product, many= False)
    return Response(serializer.data)
