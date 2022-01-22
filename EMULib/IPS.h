/** EMULib Emulation Library *********************************/
/**                                                         **/
/**                          IPS.h                          **/
/**                                                         **/
/** This file contains declarations for the .IPS patch file **/
/** support. See IPS.c for implementation.                  **/
/**                                                         **/
/** Copyright (C) Marat Fayzullin 1996-2021                 **/
/**     You are not allowed to distribute this software     **/
/**     commercially. Please, notify me, if you make any    **/
/**     changes to this file.                               **/
/*************************************************************/
#ifndef IPS_H
#define IPS_H

#ifndef BYTE_TYPE_DEFINED
#define BYTE_TYPE_DEFINED
typedef unsigned char byte;
#endif

/** GetIpsFileName() *****************************************/
/** Construct .IPS or .ips filename based on input and      **/
/** existing files. Extension .ips takes precedence.        **/
/** Pointer must be free()'d by caller.                     **/
/*************************************************************/
char* GetIpsFileName(const char* FileName);

/** ApplyIPS() ***********************************************/
/** Loads patches from an .IPS file and applies them to the **/
/** given data buffer. Returns number of patches applied.   **/
/*************************************************************/
unsigned int ApplyIPS(const char *FileName,unsigned char *Data,unsigned int Size);

/** CreateIPS() **********************************************/
/** Creates .IPS data from pre/post data of size inSize.    **/
/** Sets size of created patch in ipsSize, and returns ptr  **/
/** to patch, or NULL on failure. Pointer must be free()'d  **/
/** by caller                                               **/
/*************************************************************/
byte* CreateIPS(byte *SrcData,byte *NewData,unsigned int inSize,unsigned int* ipsSize);

/** MeasureIPS() *********************************************/
/** Find total data size assumed by a given .IPS file.      **/
/*************************************************************/
unsigned int MeasureIPS(const char *FileName);

#endif /* IPS_H */
