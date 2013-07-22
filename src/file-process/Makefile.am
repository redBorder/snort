AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libfileAPI.a

libfileAPI_a_SOURCES = file_service.c file_service.h file_service_config.c file_service_config.h file_api.h \
                       file_mime_process.h file_mime_process.c file_resume_block.c file_resume_block.h \
                       file_mime_config.c file_mime_config.h \
                       ../sfutil/sf_email_attach_decode.c ../sfutil/sf_email_attach_decode.h  

INCLUDES = @INCLUDES@

SUBDIRS = libs