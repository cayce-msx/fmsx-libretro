/** EMULib Emulation Library *********************************/
/**                                                         **/
/**                          IPS.c                          **/
/**                                                         **/
/** This file contains support for the .IPS patch file      **/
/** format. See IPS.h for declarations.                     **/
/**                                                         **/
/** Copyright (C) Marat Fayzullin 1996-2021                 **/
/**     You are not allowed to distribute this software     **/
/**     commercially. Please, notify me, if you make any    **/
/**     changes to this file.                               **/
/*************************************************************/
#include "IPS.h"

#include "libretro.h"
extern retro_log_printf_t log_cb;

#include <streams/file_stream_transforms.h>

#define FILE_LIMIT 0x1000000    // 16MB Max size of an IPS file - 3byte int
#define RECORD_LIMIT 0xFFFF     // Max size of an individual record - 2 byte int
#define EOF_CODE 0x454f46       // IPS file footer 'EOF'

/** MeasureIPS() *********************************************/
/** Find total data size assumed by a given .IPS file.      **/
/*************************************************************/
unsigned int MeasureIPS(const char *FileName)
{
  return(ApplyIPS(FileName,0,0));
}

/** GetIpsFileName() *****************************************/
/** Construct .IPS or .ips filename based on input and      **/
/** existing files. Extension .ips takes precedence.        **/
/** Pointer must be free()'d by caller.                     **/
/*************************************************************/
char* GetIpsFileName(const char* FileName)
{
  RFILE *F;
  char *IpsFileName = malloc(strlen(FileName)+1), *end,*cur;

  strcpy(IpsFileName, FileName);
  cur = end = IpsFileName + strlen(IpsFileName);
  while (cur > IpsFileName && *cur != '.') --cur;
  if (!(*cur == '.' && end - cur > 3)) { free(IpsFileName);return NULL; }

  /* first check if .ips exists, then default to .IPS */
  strcpy(cur+1, "ips");
  if(!filestream_exists(IpsFileName))
    strcpy(cur+1, "IPS");

  return IpsFileName;
}

/** ApplyIPS() ***********************************************/
/** Loads patches from an .IPS file and applies them to the **/
/** given data buffer. Returns number of patches applied.   **/
/*************************************************************/
unsigned int ApplyIPS(const char *FileName,unsigned char *Data,unsigned int Size)
{
  unsigned char Buf[16];
  unsigned int Result,Count,J,N;
  RFILE *F;
  char *IpsFileName;

  if (!(IpsFileName = GetIpsFileName(FileName))) return(0);

  F = rfopen(IpsFileName,"rb");
  free(IpsFileName);
  if(!F) return(0);

  /* Verify file header */
  if(rfread(Buf,1,5,F)!=5)   { rfclose(F);return(0); }
  if(memcmp(Buf,"PATCH",5))  { rfclose(F);return(0); }

  for(Result=0,Count=1;rfread(Buf,1,5,F)==5;++Count)
  {
    J = Buf[2]+((unsigned int)Buf[1]<<8)+((unsigned int)Buf[0]<<16);
    N = Buf[4]+((unsigned int)Buf[3]<<8);

    /* Apparently, these may signal the end of .IPS file */
    if((J==0xFFFFFF) || !memcmp(Buf,"EOF",3)) break;

    /* If patching with a block of data... */
    if(N)
    {
      /* Copying data */
      if(!Data)
      {
        /* Just measuring patch size */
        if(Result<J+N) Result=J+N;
        if(rfseek(F,N,SEEK_CUR)<0) break;
      }
      else if(J+N>Size)
      {
        if (log_cb) log_cb(RETRO_LOG_WARN,"IPS: Failed applying COPY patch #%d to 0x%X..0x%X of 0x%X bytes.\n",Count,J,J+N-1,Size);
        if(rfseek(F,N,SEEK_CUR)<0) break;
      }
      else if(rfread(Data+J,1,N,F)==N)
      {
        if (log_cb) log_cb(RETRO_LOG_DEBUG,"IPS: Applied COPY patch #%d to 0x%X..0x%X.\n",Count,J,J+N-1);
        ++Result;
      }
      else
      {
        if (log_cb) log_cb(RETRO_LOG_WARN,"IPS: Failed reading COPY patch #%d from the file.\n",Count);
        break;
      }
    }
    else
    {
      /* Filling with a value */
      if(rfread(Buf,1,3,F)!=3)
      {
        if(Data && log_cb) log_cb(RETRO_LOG_WARN,"IPS: Failed reading FILL patch #%d from the file.\n",Count);
        break;
      }

      /* Compute fill length */
      N = ((unsigned int)Buf[0]<<8)+Buf[1];

      if(!Data)
      {
        if(Result<J+N) Result=J+N;
      }
      else if(!N || (J+N>Size))
      {
        if (log_cb) log_cb(RETRO_LOG_WARN,"IPS: Failed applying FILL patch #%d (0x%02X) to 0x%X..0x%X of 0x%X bytes.\n",Count,Buf[2],J,J+N-1,Size);
      }
      else
      {
        if (log_cb) log_cb(RETRO_LOG_DEBUG,"IPS: Applied FILL patch #%d (0x%02X) to 0x%X..0x%X.\n",Count,Buf[2],J,J+N-1);
        memset(Data+J,Buf[2],N);
        ++Result;
      }
    }
  }

  rfclose(F);
  return(Result);
}

void write_record(byte* ips,unsigned int* ips_size, int curr_offset, byte* record_data, unsigned int record_size)
{
  ips[(*ips_size)++] = (curr_offset>>16)&0xff;
  ips[(*ips_size)++] = (curr_offset>> 8)&0xff;
  ips[(*ips_size)++] = (curr_offset    )&0xff;
  ips[(*ips_size)++] = (record_size>> 8)&0xff;
  ips[(*ips_size)++] = (record_size    )&0xff;
  memcpy(&ips[*ips_size], record_data, record_size);
  *ips_size += record_size;
}

void ensure_length(byte **buffer, int required_capacity, int *capacity)
{
  byte *copy;
  int new_capacity;

  if(required_capacity <= *capacity) return;

  for(new_capacity=*capacity; new_capacity<required_capacity; new_capacity<<=1);
  copy = malloc(new_capacity);
  memcpy(copy, *buffer, *capacity);
  free(*buffer);
  *buffer = copy;
  *capacity=new_capacity;
}

// ported from https://github.com/kylon/Lipx/blob/master/lipx.py
// format: https://zerosoft.zophar.net/ips.php
byte* CreateIPS(byte *original_data,byte *modified_data,unsigned int in_size,unsigned int* ips_size)
{
  bool record_begun = false;
  byte* record = (byte*)malloc(RECORD_LIMIT);
  int CurIpsBufSize = 1024;
  byte *ips = (byte*)malloc(CurIpsBufSize);
  int pos;
  int recordIdx;
  int curr_offset;

  memcpy(ips, "PATCH", 5);
  *ips_size = 5;

  // Format (all integers in BIG endian):
  // [OFFSET into file : 3bytes][SIZE of record : 2bytes][BYTES : SIZEbytes]
  for(pos=0;pos<in_size;pos++)
  {
    if (CurIpsBufSize>FILE_LIMIT)
    {
      free(record);
      free(ips);
      return NULL;
    }
    if (!record_begun)
    {
      if (in_size <= pos || modified_data[pos] != original_data[pos])
      {
        record_begun = true;
        recordIdx=0;
        if (pos == EOF_CODE) record[recordIdx++] = modified_data[pos - 1];
        record[recordIdx++] = modified_data[pos];
        // Save the absolute offset for this record
        curr_offset = pos;
        if (pos == EOF_CODE) curr_offset--;
        // If we're at the last address, close the record and write to the patch file
        if (curr_offset == in_size - 1)
        {
          record_begun = false;
          ensure_length(&ips, *ips_size + 5 + 1, &CurIpsBufSize);
          write_record(ips, ips_size, curr_offset, record, 1);
        }
      }
    }
    else
    {
      // Records have a max size of 0xFFFF as the size header is a short
      // Check our current position and if we at the max size end the record and start a new one
      if (recordIdx == RECORD_LIMIT - 1)
      {
        if (log_cb) log_cb(RETRO_LOG_DEBUG,"Truncating overlong record: %d\n", recordIdx);
        record_begun = false;
        record[recordIdx++] = modified_data[pos];
        ensure_length(&ips, *ips_size + 5 + recordIdx, &CurIpsBufSize);
        write_record(ips, ips_size, curr_offset, record, recordIdx);
      }
      // Append diff data to the record
      else if ((in_size <= pos || modified_data[pos] != original_data[pos]) && pos != in_size - 1)
      {
        // Continue Record
        record[recordIdx++] = modified_data[pos];
      }
      // END OF RECORD
      else
      {
        record_begun = false;
        ensure_length(&ips, *ips_size + 5 + recordIdx, &CurIpsBufSize);
        write_record(ips, ips_size, curr_offset, record, recordIdx);
      }
    }
  }

  ensure_length(&ips, *ips_size + 3, &CurIpsBufSize);
  memcpy(&ips[*ips_size], "EOF", 3);
  *ips_size += 3;

  free(record);

  return ips;
}
