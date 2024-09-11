#!/bin/bash

# Correr IdP
cd idp
py app.py

# Correr web
cd ../serviço
py app.py
