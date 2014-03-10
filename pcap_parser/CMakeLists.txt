# set( component_SOURCES ) # Add the source-files for the component here
# Optionally you can use file glob (uncomment the next line)
file( GLOB component_SOURCES *.cpp )
add_library( pcap_parser ${component_SOURCES} )
