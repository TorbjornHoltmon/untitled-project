# Image api hosted on azure functions

# IMPORTANT

Because we have pure typescript packages, these have to be built and bundled into the azure function.

ALL DEPENDENCIES THAT ARE NOT PURE TYPESCRIPT NEED TO BE IN BOTH package.json AND azure/package.json

why?

We build and bundle our typescript packages, defined by the "noExternal" field in vite.
All other packages should be external.
A normal "npm install" is done in the azure folder before deployment.

Azure functions ship the whole node_modules folder.
