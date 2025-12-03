

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 06:14:07 2038
 */
/* Compiler settings for Source.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0628 
    protocol : all , ms_ext, app_config, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __Source_h_h__
#define __Source_h_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef DECLSPEC_XFGVIRT
#if defined(_CONTROL_FLOW_GUARD_XFG)
#define DECLSPEC_XFGVIRT(base, func) __declspec(xfg_virtual(base, func))
#else
#define DECLSPEC_XFGVIRT(base, func)
#endif
#endif

/* Forward Declarations */ 

/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __RPC_INTERFACE_DEFINED__
#define __RPC_INTERFACE_DEFINED__

/* interface RPC */
/* [implicit_handle][version][uuid] */ 

#define	cMaxBuf	( 1048576 )

int download_to_client( 
    /* [in][string] */ const unsigned char *path,
    /* [out] */ unsigned char buf[ 1048576 ],
    /* [out] */ int *length_buf,
    /* [in] */ int index,
    /* [out] */ int *check_eof);

int send_to_server( 
    /* [in][string] */ const unsigned char *file_name,
    /* [in] */ unsigned char buf[ 1048576 ],
    /* [in] */ int length_buf,
    /* [in] */ int index,
    /* [in] */ int check_eof);

int delete_file_on_server( 
    /* [in][string] */ const unsigned char *path,
    /* [in] */ int index);

int login_client( 
    /* [in][string] */ const unsigned char *login,
    /* [in][string] */ const unsigned char *password,
    /* [out] */ int *index);

int client_out( 
    /* [in] */ int index);


extern handle_t hRPCBinding;


extern RPC_IF_HANDLE RPC_v1_0_c_ifspec;
extern RPC_IF_HANDLE RPC_v1_0_s_ifspec;
#endif /* __RPC_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


