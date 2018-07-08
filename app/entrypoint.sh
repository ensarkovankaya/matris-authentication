#!/usr/bin/env bash
set -e

mkdir -p logs # Create logs folder if not exits

install () {
    # Install Dependencies
    if [ "$NODE_ENV" == "development" ] || [ "$NODE_ENV" == "dev" ]; then
        npm install
    else
        npm install --only=prod
    fi
}

if [ "$1" == "bash" ]; then
    /usr/bin/env bash
elif [ "$1" == "test" ]; then
    NODE_ENV=test
    npm run test
elif [ "$1" == "install" ]; then
    install
else
    install
    # If environment development use nodemon to watch file changes
    # Otherwise just run the server
    if [ "$NODE_ENV" == "development" ]; then
        npm run watch
    else
        npm run start
    fi
fi