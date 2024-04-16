#!/usr/bin/env perl

use strict;
use warnings;

use Compress::Raw::Lzma qw (LZMA_STREAM_END LZMA_DICT_SIZE_MIN);
use Crypt::CBC;
use Digest::CRC qw (crc32);
use Digest::SHA qw (sha256);
use Encode;

# author:
# philsmd

# version:
# 0.01

# dependencies:
# Compress::Raw::Lzma

#
# Constants
#

my $TOOL_NAME    = "7z_strip_header_encryption";
my $TOOL_VERSION = "0.01";

my $SEVEN_ZIP_SIGNATURE_LEN         = 32;
my $SEVEN_ZIP_OUTPUT_NAME           = "tmp";
my $SEVEN_ZIP_OUTPUT_NAME_MAX_TRIES = 20;
my $SEVEN_ZIP_FILE_EXTENSION        = ".7z";

my $SHOW_UNSUPPORTED_CODER_WARNING = 1;
my @SUPPORTED_DECOMPRESSORS = (); # within this list we only need values ranging from 1 to 7
my @SUPPORTED_PREPROCESSORS = (); # BCJ2 can be "supported" by ignoring CRC
my %SEVEN_ZIP_COMPRESSOR_NAMES   = (1 => "LZMA1", 2 => "LZMA2", 3 => "PPMD", 6 => "BZIP2", 7 => "DEFLATE",
                                    (1 << 4) => "BCJ", (2 << 4) => "BCJ2", (3 << 4) => "PPC", (4 << 4) => "IA64",
                                    (5 << 4) => "ARM", (6 << 4) => "ARMT", (7 << 4) => "SPARC", (9 << 4) => "DELTA");
my $SUPPORT_MULTIPLE_DECOMPRESSORS = 0; # does the cracker support more than one compressing algorithms for the same file (e.g. LZMA2 + LZMA1)
my $SUPPORT_MULTIPLE_PREPROCESSORS = 0; # does the cracker support more than one preprocessing filters for the same file (e.g. BCJ + Delta)


# 7-zip specific stuff

my $LZMA2_MIN_COMPRESSED_LEN = 16; # the raw data (decrypted) needs to be at least: 3 + 1 + 1, header (start + size) + at least one byte of data + end
                                   # therefore we need to have at least one AES BLOCK (128 bits = 16 bytes)

# header

my $SEVEN_ZIP_MAGIC = "7z\xbc\xaf\x27\x1c";

my $SEVEN_ZIP_END                = "\x00";
my $SEVEN_ZIP_HEADER             = "\x01";
my $SEVEN_ZIP_ARCHIVE_PROPERTIES = "\x02";
my $SEVEN_ZIP_ADD_STREAMS_INFO   = "\x03";
my $SEVEN_ZIP_MAIN_STREAMS_INFO  = "\x04";
my $SEVEN_ZIP_FILES_INFO         = "\x05";
my $SEVEN_ZIP_ENCODED_HEADER     = "\x17";
my $SEVEN_ZIP_PACK_INFO          = "\x06";
my $SEVEN_ZIP_UNPACK_INFO        = "\x07";
my $SEVEN_ZIP_SUBSTREAMS_INFO    = "\x08";
my $SEVEN_ZIP_SIZE               = "\x09";
my $SEVEN_ZIP_CRC                = "\x0a";
my $SEVEN_ZIP_FOLDER             = "\x0b";
my $SEVEN_ZIP_UNPACK_SIZE        = "\x0c";
my $SEVEN_ZIP_NUM_UNPACK_STREAM  = "\x0d";
my $SEVEN_ZIP_EMPTY_STREAM       = "\x0e";
my $SEVEN_ZIP_EMPTY_FILE         = "\x0f";
my $SEVEN_ZIP_ANTI_FILE          = "\x10";
my $SEVEN_ZIP_NAME               = "\x11";
my $SEVEN_ZIP_CREATION_TIME      = "\x12";
my $SEVEN_ZIP_ACCESS_TIME        = "\x13";
my $SEVEN_ZIP_MODIFICATION_TIME  = "\x14";
my $SEVEN_ZIP_WIN_ATTRIBUTE      = "\x15";
my $SEVEN_ZIP_START_POS          = "\x18";
my $SEVEN_ZIP_DUMMY              = "\x19";

my $SEVEN_ZIP_MAX_PROPERTY_TYPE  = 2 ** 30; # 1073741824
my $SEVEN_ZIP_NOT_EXTERNAL       = "\x00";
my $SEVEN_ZIP_EXTERNAL           = "\x01";
my $SEVEN_ZIP_ALL_DEFINED        = "\x01";
my $SEVEN_ZIP_FILE_NAME_END      = "\x00\x00";

# codec

my $SEVEN_ZIP_AES               = "\x06\xf1\x07\x01"; # all the following codec values are from CPP/7zip/Archive/7z/7zHeader.h

my $SEVEN_ZIP_LZMA1             = "\x03\x01\x01";
my $SEVEN_ZIP_LZMA2             = "\x21";
my $SEVEN_ZIP_PPMD              = "\x03\x04\x01";
my $SEVEN_ZIP_BCJ               = "\x03\x03\x01\x03";
my $SEVEN_ZIP_BCJ2              = "\x03\x03\x01\x1b";
my $SEVEN_ZIP_PPC               = "\x03\x03\x02\x05";
my $SEVEN_ZIP_ALPHA             = "\x03\x03\x03\x01";
my $SEVEN_ZIP_IA64              = "\x03\x03\x04\x01";
my $SEVEN_ZIP_ARM               = "\x03\x03\x05\x01";
my $SEVEN_ZIP_ARMT              = "\x03\x03\x07\x01";
my $SEVEN_ZIP_SPARC             = "\x03\x03\x08\x05";
my $SEVEN_ZIP_BZIP2             = "\x04\x02\x02";
my $SEVEN_ZIP_DEFLATE           = "\x04\x01\x08";
my $SEVEN_ZIP_DELTA             = "\x03";
my $SEVEN_ZIP_COPY              = "\x00";

# hash format

my $SEVEN_ZIP_DEFAULT_POWER     = 19;
my $SEVEN_ZIP_DEFAULT_IV        = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

my $SEVEN_ZIP_UNCOMPRESSED       =   0;
my $SEVEN_ZIP_LZMA1_COMPRESSED   =   1;
my $SEVEN_ZIP_LZMA2_COMPRESSED   =   2;
my $SEVEN_ZIP_PPMD_COMPRESSED    =   3;
my $SEVEN_ZIP_BZIP2_COMPRESSED   =   6;
my $SEVEN_ZIP_DEFLATE_COMPRESSED =   7;

my $SEVEN_ZIP_BCJ_PREPROCESSED   =   1;
my $SEVEN_ZIP_BCJ2_PREPROCESSED  =   2;
my $SEVEN_ZIP_PPC_PREPROCESSED   =   3;
my $SEVEN_ZIP_IA64_PREPROCESSED  =   4;
my $SEVEN_ZIP_ARM_PREPROCESSED   =   5;
my $SEVEN_ZIP_ARMT_PREPROCESSED  =   6;
my $SEVEN_ZIP_SPARC_PREPROCESSED =   7;
                                 #   8 conflicts with SEVEN_ZIP_TRUNCATED (128 == 0x80 == 8 << 4)
my $SEVEN_ZIP_DELTA_PREPROCESSED =   9;

my $SEVEN_ZIP_TRUNCATED          = 128; # (0x80 or 0b10000000)


#
# Helper functions
#

sub usage
{
  my $prog_name = shift;

  print STDERR "Usage: $prog_name [Option]... <7-Zip file>...\n\n";

  print STDERR "Attention: the password is of course a required command line argument\n";

  print "\n";

  print "[ Option ]\n\n";

  print "Options Short, Long | Type | Description                                  | Example\n";
  print "====================+======+==============================================+=========\n";
  print "-p, --password      |      | Header encryption password (required)        |\n";
  print "-v, --version       |      | Print version                                |\n";
  print "-h, --help          |      | Print help                                   |\n";
  print "-o, --output        | Str  | File to write to (output 7-Zip archive file) | -o ab.7z\n";
  print "\n";
}

sub globbing_on_windows
{
  my @file_list = @_;

  my $os = $^O;

  if (($os eq "MSWin32") || ($os eq "Win32"))
  {
    my $windows_globbing_module = "File::Glob";
    my $windows_globbing = "bsd_glob";

    if (eval "require $windows_globbing_module")
    {
      no strict 'refs';

      $windows_globbing_module->import ($windows_globbing);

      my @new_file_list = ();

      foreach my $item (@file_list)
      {
        push (@new_file_list, $windows_globbing-> ($item));
      }

      @file_list = @new_file_list;
    }
  }

  return @file_list;
}

sub get_splitted_archive_raw_name
{
  my $full_name = shift;

  my $name_index = rindex ($full_name, ".");

  my $name = substr ($full_name, 0, $name_index);

  return $name;
}

my $memory_buffer_read_offset = 0;

sub my_read
{
  my $input  = shift;
  my $length = shift;

  my $type_of_input = ref ($input);

  my $output_buffer = "";

  if ($type_of_input eq "GLOB")
  {
    read $input, $output_buffer, $length;
  }
  elsif ($type_of_input eq "HASH")
  {
    my $cur_file_handle = $$input{0}{'fh'};
    my $cur_file_number = $$input{0}{'num'};

    my $bytes_read = 0;

    while ($bytes_read != $length)
    {
      my $name  = $$input{$cur_file_number}{'name'};
      my $start = $$input{$cur_file_number}{'start'};
      my $size  = $$input{$cur_file_number}{'size'};

      my $cur_file_bytes_avail = ($start + $size) - $memory_buffer_read_offset;

      if ($cur_file_bytes_avail < 1)
      {
        print STDERR "ERROR: failed to get the correct file offsets of splitted archive file '$name'\n";

        exit (1);
      }

      my $total_bytes_to_read  = $length - $bytes_read;
      my $bytes_to_read = $total_bytes_to_read;

      if ($bytes_to_read > $cur_file_bytes_avail)
      {
        $bytes_to_read = $cur_file_bytes_avail;
      }

      # append the current bytes read from the file to the overall output buffer

      my $temp_output_buffer = "";

      my $bytes = read ($cur_file_handle, $temp_output_buffer, $bytes_to_read);

      $output_buffer .= $temp_output_buffer;

      if ($bytes != $bytes_to_read)
      {
        print STDERR "ERROR: could not read from splitted 7z file '$name'\n";

        exit (1);
      }

      $bytes_read += $bytes_to_read;
      $memory_buffer_read_offset += $bytes_to_read;

      # the following case only happens if we need to read across 2 or more files

      if ($bytes_read != $length)
      {
        # we exhausted the current file, move to the next one!

        close ($cur_file_handle);

        $cur_file_number++;

        if (! exists ($$input{$cur_file_number}))
        {
          my $name_prefix = get_splitted_archive_raw_name ($name);

          print STDERR "ERROR: could not open part #$cur_file_number of the splitted archive file '$name_prefix'\n";

          exit (1);
        }

        my $name = $$input{$cur_file_number}{'name'};

        if (! open ($cur_file_handle, "<$name"))
        {
          print STDERR "ERROR: could not open the splitted archive file '$name' for reading\n";

          exit (1);
        }

        $$input{0}{'fh'}  = $cur_file_handle;
        $$input{0}{'num'} = $cur_file_number;
      }
    }
  }
  else
  {
    $output_buffer = substr ($$input, $memory_buffer_read_offset, $length);

    $memory_buffer_read_offset += $length;
  }

  return $output_buffer;
}

sub aes_derive_key
{
  my $header_pass = shift;
  my $number_cycles_power = shift;

  my $pass = encode ("UTF-16LE", $header_pass);

  my $pass_buf = "";

  my $rounds = 1 << $number_cycles_power;

  for (my $i = 0; $i < $rounds; $i++)
  {
    my $num_buf = "";

    $num_buf .= pack ("V", $i);
    $num_buf .= "\x00" x 4;

    # this would be better but only works on 64-bit systems:
    # $num_buf = pack ("q", $i);

    $pass_buf .= sprintf ("%s%s", $pass, $num_buf);
  }

  return sha256 ($pass_buf);
}

sub aes_init_context
{
  my $key = shift;
  my $iv_buf = shift;
  my $iv_len = shift;

  my $iv_padding_len = 0;

  my $iv = substr ($iv_buf, 0, $iv_len);

  if ($iv_len < 16)
  {
    $iv_padding_len = 16 - $iv_len;
  }

  $iv .= "\x00" x $iv_padding_len;

  my $aes = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    key         => $key,
    keysize     => 32,
    literal_key => 1,
    iv          => $iv,
    header      => "none",
    padding     => "none",
  });

  return $aes;
}

sub write_output_file
{
  my $data_buf  = shift;
  my $file_name = shift;

  print "Writing " . length ($data_buf) . " bytes to file '$file_name'.\n";

  # file writing:

  my $out_file;

  if (! open ($out_file, ">", $file_name))
  {
    print STDERR "ERROR: could not open file '$file_name' for writing\n";

    exit (1);
  }

  binmode ($out_file);

  print $out_file $data_buf;

  close ($out_file);
}

sub seven_zip_signature_header
{
  my $signature_header = shift;
  my $header_crc       = shift;

  my $ret = "";

  my $major_version = $signature_header->{'major_version'};

  $ret .= chr ($major_version);

  my $minor_version = $signature_header->{'minor_version'};

  $ret .= chr ($minor_version);

  my $signature_header_buf = "";


  my $tmp_val;

  $tmp_val = $signature_header->{'next_header_offset'};

  for (my $i = 0; $i < 8; $i++)
  {
    $signature_header_buf .= chr ($tmp_val & 0xff);

    $tmp_val >>= 8;
  }


  $tmp_val = $signature_header->{'next_header_size'};

  for (my $i = 0; $i < 8; $i++)
  {
    $signature_header_buf .= chr ($tmp_val & 0xff);

    $tmp_val >>= 8;
  }


  $tmp_val = $header_crc;

  for (my $i = 0; $i < 4; $i++) # or use: $signature_header_buf .= pack ("L<",  $header_crc)
  {
    $signature_header_buf .= chr ($tmp_val & 0xff);

    $tmp_val >>= 8;
  }

  my $signature_crc = crc32 ($signature_header_buf);

  $ret .= pack ("L<", $signature_crc);

  $ret .= $signature_header_buf;

  return $ret;
}

sub lzma_alone_header_field_encode
{
  my $num = shift;
  my $length = shift;

  my $value;

  my $length_doubled = $length * 2;
  my $big_endian_val = pack ("H*", sprintf ("%0${length_doubled}x", $num));

  # what follows is just some easy way to convert endianess (there might be better ways of course)

  $value = "";

  for (my $i = $length - 1; $i >= 0; $i--)
  {
    $value .= substr ($big_endian_val, $i, 1);
  }

  return $value;
}

sub lzma_properties_decode
{
  my $attributes = shift;

  my $lclppb;

  $lclppb = substr ($attributes, 0, 1);

  my @data;

  #data[0] is the lclppb value

  $data[1] = ord (substr ($attributes, 1, 1));
  $data[2] = ord (substr ($attributes, 2, 1));
  $data[3] = ord (substr ($attributes, 3, 1));
  $data[4] = ord (substr ($attributes, 4, 1));

  my $dict_size = $data[1] | $data[2] << 8 | $data[3] << 16 | $data[4] << 24;

  if ($dict_size < LZMA_DICT_SIZE_MIN)
  {
    $dict_size = LZMA_DICT_SIZE_MIN;
  }

  my $d = ord ($lclppb);

  my $lc = int ($d % 9);
     $d  = int ($d / 9);
  my $pb = int ($d / 5);
  my $lp = int ($d % 5);

  return ($lclppb, $dict_size, $lc, $pb, $lp);
}

sub check_attributes
{
  my $attributes     = shift;
  my $is_truncated   = shift;
  my $file_path      = shift;
  my $padding_attack = shift;
  my $data_len       = shift;
  my $warning_shown  = shift;

  my $additional_attributes = "";
  my $error = 0;

  # Defaults:

  my $type_of_compression  = $SEVEN_ZIP_UNCOMPRESSED;
  my $type_of_preprocessor = $SEVEN_ZIP_UNCOMPRESSED;

  my $compression_attributes  = "";
  my $preprocessor_attributes = "";

  my $codec_count        = 0;
  my $compressor_count   = 0;
  my $preprocessor_count = 0;

  my $show_warning = 0;

  my $steps_involved = "";

  foreach my $attribute (@$attributes)
  {
    my $is_preprocessor = $attribute->{'is_preprocessor'};

    my $cur_type = $attribute->{'type'};

    my $attr = "";

    if (defined ($attribute->{'attributes'}))
    {
      $attr = $attribute->{'attributes'};
    }

    if ($is_preprocessor == 0)
    {
      if (grep (/^$cur_type$/, @SUPPORTED_DECOMPRESSORS) == 0)
      {
        $show_warning = 1;
      }

      $compressor_count++;

      if ($compressor_count == 1)
      {
        $type_of_compression = $cur_type;

        if ($preprocessor_count == 0)
        {
          $compression_attributes = $attr;
        }
        else # special case: preprocessor after compressing (unlikely)
        {
          $compression_attributes = "," . (($cur_type << 4) + $codec_count) . "_" . $attr;
        }
      }
      else
      {
        $compression_attributes .= "," . (($cur_type << 4) + $codec_count) . "_" . $attr;
      }

      # cosmetic (warning message):

      if (length ($steps_involved) > 0)
      {
        $steps_involved .= ", ";
      }

      $steps_involved .= "decompressed using " . $SEVEN_ZIP_COMPRESSOR_NAMES{$cur_type};
    }
    else # if ($is_preprocessor == 1)
    {
      if (grep (/^$cur_type$/, @SUPPORTED_PREPROCESSORS) == 0)
      {
        $show_warning = 1;
      }

      $preprocessor_count++;

      if ($preprocessor_count == 1)
      {
        $type_of_preprocessor = $cur_type;

        $preprocessor_attributes = $attr;
      }
      else
      {
        $preprocessor_attributes .= "," . (($cur_type << 4) + $codec_count) . "_" . $attr;
      }

      # cosmetic (warning message):

      if (length ($steps_involved) > 0)
      {
        $steps_involved .= ", ";
      }

      $steps_involved .= "processed using " . $SEVEN_ZIP_COMPRESSOR_NAMES{$cur_type << 4};
    }

    $codec_count++;

    if ($codec_count >= 16)
    {
      print STDERR "WARNING: unsupported amount of compression algorithms/preprocessing filters for the file '". $file_path . "',\n";

      $error = 1;

      last;
    }
  }

  # cosmetic: replace the last "," with an "and"

  my $last_comma_in_steps = rindex ($steps_involved, ",");

  if ($last_comma_in_steps >= 0)
  {
    $steps_involved = substr ($steps_involved, 0, $last_comma_in_steps) . " and " .
                      substr ($steps_involved, $last_comma_in_steps + 2);
  }

  # show a warning if the decompression algorithm is currently not supported by the cracker

  if (($SHOW_UNSUPPORTED_CODER_WARNING == 0) ||
      ($show_warning  == 0)                  ||
      ($is_truncated  == 1)                  ||
      ($warning_shown == 1))
  {
    # no warning(s) needed
  }
  else
  {
    print STDERR "WARNING: to correctly verify the CRC checksum of the data contained within the file '". $file_path . "',\n";
    print STDERR "the data must be " . $steps_involved . ".\n";
    print STDERR "\n";
  }

  # special case: all compressors/filters are supported, but cracker does NOT support combinations:

  if ($compressor_count > 1)
  {
    if ($SUPPORT_MULTIPLE_DECOMPRESSORS == 0)
    {
      if (($warning_shown == 0) &&
          ($show_warning  == 0))
      {
        print STDERR "WARNING: We do not currently support combining/cascading multiple decompression algorithms\n";
        print STDERR "\n";
      }

      $show_warning = 1;
    }
  }

  if ($preprocessor_count > 1)
  {
    if ($SUPPORT_MULTIPLE_PREPROCESSORS == 0)
    {
      if (($warning_shown == 0) &&
          ($show_warning  == 0))
      {
        print STDERR "WARNING: We do not currently support combining/cascading multiple preprocessing filters\n";
        print STDERR "\n";
      }

      $show_warning = 1;
    }
  }

  $additional_attributes = $compression_attributes;

  if (length ($preprocessor_attributes) > 0) # special case: we need both attributes
  {
    $additional_attributes .= "\$" . $preprocessor_attributes;
  }

  my $type_of_data = $SEVEN_ZIP_UNCOMPRESSED; # this variable will hold the "number" after the "$7z$" hash signature

  if ($is_truncated == 1)
  {
    $type_of_data = $SEVEN_ZIP_TRUNCATED; # note: this means that we neither need the crc_len, nor the coder attributes
  }
  else
  {
    $type_of_data = ($type_of_preprocessor << 4) | $type_of_compression;
  }

  return ($type_of_data, $additional_attributes, $show_warning, $error);
}

sub fill_additional_attribute_list
{
  my $coder            = shift;
  my $file_path        = shift;
  my $coder_attributes = shift;

  my $error = 0;

  my $codec_id = $$coder->{'codec_id'};

  my $type = $SEVEN_ZIP_UNCOMPRESSED;

  my $is_preprocessor = 0;

  if ($codec_id eq $SEVEN_ZIP_LZMA1)
  {
    $type = $SEVEN_ZIP_LZMA1_COMPRESSED;
  }
  elsif ($codec_id eq $SEVEN_ZIP_LZMA2)
  {
    $type = $SEVEN_ZIP_LZMA2_COMPRESSED;
  }
  elsif ($codec_id eq $SEVEN_ZIP_PPMD)
  {
    $type = $SEVEN_ZIP_PPMD_COMPRESSED;
  }
  elsif ($codec_id eq $SEVEN_ZIP_BZIP2)
  {
    $type = $SEVEN_ZIP_BZIP2_COMPRESSED;
  }
  elsif ($codec_id eq $SEVEN_ZIP_DEFLATE)
  {
    $type = $SEVEN_ZIP_DEFLATE_COMPRESSED;
  }
  elsif ($codec_id eq $SEVEN_ZIP_COPY)
  {
    return 0; # don't add it to our coder_attributes list, it's a NO-OP
  }
  elsif ($codec_id eq $SEVEN_ZIP_BCJ)
  {
    $type = $SEVEN_ZIP_BCJ_PREPROCESSED;

    $is_preprocessor = 1;
  }
  elsif ($codec_id eq $SEVEN_ZIP_BCJ2)
  {
    $type = $SEVEN_ZIP_BCJ2_PREPROCESSED;

    $is_preprocessor = 1;
  }
  elsif ($codec_id eq $SEVEN_ZIP_PPC)
  {
    $type = $SEVEN_ZIP_PPC_PREPROCESSED;

    $is_preprocessor = 1;
  }
  elsif ($codec_id eq $SEVEN_ZIP_IA64)
  {
    $type = $SEVEN_ZIP_IA64_PREPROCESSED;

    $is_preprocessor = 1;
  }
  elsif ($codec_id eq $SEVEN_ZIP_ARM)
  {
    $type = $SEVEN_ZIP_ARM_PREPROCESSED;

    $is_preprocessor = 1;
  }
  elsif ($codec_id eq $SEVEN_ZIP_ARMT)
  {
    $type = $SEVEN_ZIP_ARMT_PREPROCESSED;

    $is_preprocessor = 1;
  }
  elsif ($codec_id eq $SEVEN_ZIP_SPARC)
  {
    $type = $SEVEN_ZIP_SPARC_PREPROCESSED;

    $is_preprocessor = 1;
  }
  elsif ($codec_id eq $SEVEN_ZIP_DELTA)
  {
    $type = $SEVEN_ZIP_DELTA_PREPROCESSED;

    $is_preprocessor = 1;
  }
  else
  {
    print STDERR "WARNING: unsupported coder with codec id '0x" . unpack ("H*", $codec_id) . "' in file '" . $file_path . "' found.\n";

    $error = 1;

    return $error;
  }

  my $attributes = undef;

  if ($type != $SEVEN_ZIP_UNCOMPRESSED)
  {
    if (defined ($$coder->{'attributes'}))
    {
      $attributes = unpack ("H*", $$coder->{'attributes'});
    }
  }

  my %item = ('type'            => $type,
              'is_preprocessor' => $is_preprocessor,
              'attributes'      => $attributes);

  push (@$coder_attributes, \%item);

  return $error;
}

sub get_decoder_properties
{
  my $attributes = shift;

  my $salt_len;
  my $salt_buf;
  my $iv_len;
  my $iv_buf;
  my $number_cycles_power;

  # set some default values

  $salt_len = 0;
  $salt_buf = "";
  $iv_len = length ($SEVEN_ZIP_DEFAULT_IV);
  $iv_buf = $SEVEN_ZIP_DEFAULT_IV;
  $number_cycles_power = $SEVEN_ZIP_DEFAULT_POWER;

  # the most important information is encoded in first and second byte
  # i.e. the salt/iv length, number cycle power

  my $offset = 0;

  my $first_byte = substr ($attributes, 0, 1);
  $first_byte = ord ($first_byte);

  $offset++;

  $number_cycles_power = $first_byte & 0x3f;

  if (($first_byte & 0xc0) == 0)
  {
    return ($salt_len, $salt_buf, $iv_len, $iv_buf, $number_cycles_power);
  }

  $salt_len = ($first_byte >> 7) & 1;
  $iv_len   = ($first_byte >> 6) & 1;

  # combine this info with the second byte

  my $second_byte = substr ($attributes, 1, 1);
  $second_byte = ord ($second_byte);

  $offset++;

  $salt_len += ($second_byte >> 4);
  $iv_len   += ($second_byte & 0x0f);

  $salt_buf = substr ($attributes, $offset, $salt_len);

  $offset += $salt_len;

  $iv_buf = substr ($attributes, $offset, $iv_len);

  # pad the iv with zeros

  my $iv_max_length = 16;

  $iv_buf .= "\x00" x $iv_max_length;
  $iv_buf = substr ($iv_buf, 0, $iv_max_length);

  return ($salt_len, $salt_buf, $iv_len, $iv_buf, $number_cycles_power);
}

sub get_digest
{
  my $index = shift;

  my $unpack_info = shift;
  my $substreams_info = shift;

  my $digest;

  my $digests_unpack_info = $unpack_info->{'digests'};
  my $digests_substreams_info = $substreams_info->{'digests'};

  my $use_unpack_info = 0;
  my $use_substreams_info = 0;

  if (defined ($digests_unpack_info))
  {
    my $digests_unpack_info_size = 0;

    if (@$digests_unpack_info)
    {
      $digests_unpack_info_size = scalar (@$digests_unpack_info);
    }

    if ($index < $digests_unpack_info_size)
    {
      if (ref (@$digests_unpack_info[$index]) eq "HASH")
      {
        $use_unpack_info = 1;
      }
    }
  }

  if (defined ($digests_substreams_info))
  {
    my $digests_substreams_info_size = 0;

    if (@$digests_substreams_info)
    {
      $digests_substreams_info_size = scalar (@$digests_substreams_info);
    }

    if ($index < $digests_substreams_info_size)
    {
      if (ref (@$digests_substreams_info[$index]) eq "HASH")
      {
        $use_substreams_info = 1;
      }
    }
  }

  if ($use_unpack_info == 1)
  {
    $digest = @$digests_unpack_info[$index];
  }
  elsif ($use_substreams_info == 1)
  {
    $digest = @$digests_substreams_info[$index];
  }

  return $digest;
}

sub get_folder_aes_unpack_size
{
  my $unpack_info  = shift;
  my $folder_index = shift;

  my $index = $unpack_info->{'coder_unpack_sizes'}[$folder_index];

  return $unpack_info->{'unpack_sizes'}[$index];
}

sub get_uint32
{
  my $fp = shift;

  my $bytes = my_read ($fp, 4);

  return (0, 0) if (length ($bytes) != 4);

  my $num = unpack ("L", $bytes);

  return $num;
}

sub get_uint64_defined_vector
{
  my $fp = shift;

  my $number_items = shift;

  my @values;

  # first check if the values are defined

  my @defines = get_boolean_vector_check_all ($fp, $number_items);

  my $external = my_read ($fp, 1);

  if ($external eq $SEVEN_ZIP_EXTERNAL)
  {
    # ignored for now
  }

  for (my $i = 0; $i < $number_items; $i++)
  {
    my $defined = $defines[$i];

    my $value = 0;

    if ($defined != 0)
    {
      $value = get_uint64 ($fp);
    }

    $values[$i] = $value;
  }

  return @values;
}

sub read_seven_zip_files_info
{
  my $fp = shift;

  my $streams_info = shift;

  my $files_info;

  my @files;

  # NumFiles

  my $number_files = read_number ($fp);

  # init file

  for (my $i = 0; $i < $number_files; $i++)
  {
    $files[$i]->{'name_utf16'} = "";
    $files[$i]->{'attribute_defined'} = 0;
    $files[$i]->{'attribute'} = 0;
    $files[$i]->{'is_empty_stream'} = 0;
    $files[$i]->{'start_position'} = 0;
    $files[$i]->{'creation_time'} = 0;
    $files[$i]->{'access_time'} = 0;
    $files[$i]->{'modification_time'} = 0;
    $files[$i]->{'size'} = 0;
    $files[$i]->{'has_stream'} = 0;
    $files[$i]->{'is_dir'} = 0;
    $files[$i]->{'crc_defined'} = 0;
    $files[$i]->{'crc'} = "";
  }

  my $number_empty_streams = 0;

  my @empty_streams = (0) x $number_files;
  my @empty_files   = (0) x $number_files;
  my @anti_files    = (0) x $number_files;

  # loop over all properties

  while (1)
  {
    my $property_type_val = read_number ($fp);

    my $property_type = num_to_id ($property_type_val);

    if ($property_type eq $SEVEN_ZIP_END)
    {
      last;
    }

    # Size

    my $size = read_number ($fp);

    # check and act according to the type of property found

    my $is_known_type = 1;

    if ($property_type_val > $SEVEN_ZIP_MAX_PROPERTY_TYPE)
    {
      # ignore (isKnownType false in 7-Zip source code)

      my_read ($fp, $size);
    }
    else
    {
      if ($property_type eq $SEVEN_ZIP_NAME)
      {
        my $external = my_read ($fp, 1);

        if ($external eq $SEVEN_ZIP_EXTERNAL)
        {
          # TODO: not implemented yet

          return undef;
        }

        my $files_size = scalar (@files);

        for (my $i = 0; $i < $files_size; $i++)
        {
          my $name = "";

          while (1)
          {
            my $name_part = my_read ($fp, 2);

            if ($name_part eq $SEVEN_ZIP_FILE_NAME_END)
            {
              last;
            }
            else
            {
              $name .= $name_part;
            }
          }

          $files[$i]->{'name_utf16'} = $name;
        }
      }
      elsif ($property_type eq $SEVEN_ZIP_WIN_ATTRIBUTE)
      {
        my $files_size = scalar (@files);

        my @booleans = get_boolean_vector_check_all ($fp, $number_files);

        my $external = my_read ($fp, 1);

        if ($external eq $SEVEN_ZIP_EXTERNAL)
        {
          # TODO: not implemented yet

          return undef;
        }

        for (my $i = 0; $i < $number_files; $i++)
        {
          my $defined = $booleans[$i];

          $files[$i]->{'attribute_defined'} = $defined;

          if ($defined)
          {
            my $attributes = get_uint32 ($fp);

            $files[$i]->{'attribute'} = $attributes;
          }
        }
      }
      elsif ($property_type eq $SEVEN_ZIP_EMPTY_STREAM)
      {
        @empty_streams = get_boolean_vector ($fp, $number_files);

        $number_empty_streams = 0;

        # loop over all boolean and set the files attribute + empty/anti stream vector

        my $number_booleans = scalar (@empty_streams);

        for (my $i = 0; $i < $number_booleans; $i++)
        {
          my $boolean = $empty_streams[$i];

          $files[$i]->{'is_empty_stream'} = $boolean;

          if ($boolean)
          {
            $number_empty_streams++;
          }
        }

        for (my $i = 0; $i < $number_empty_streams; $i++)
        {
          $empty_files[$i] = 0;
          $anti_files[$i]  = 0;
        }
      }
      elsif ($property_type eq $SEVEN_ZIP_EMPTY_FILE)
      {
        @empty_files = get_boolean_vector ($fp, $number_empty_streams);
      }
      elsif ($property_type eq $SEVEN_ZIP_ANTI_FILE)
      {
        @anti_files = get_boolean_vector ($fp, $number_empty_streams);
      }
      elsif ($property_type eq $SEVEN_ZIP_START_POS)
      {
        my @start_positions = get_uint64_defined_vector ($fp, $number_files);

        my $number_start_positions = scalar (@start_positions);

        for (my $i = 0; $i < $number_start_positions; $i++)
        {
          $files[$i]->{'start_position'} = $start_positions[$i];
        }
      }
      elsif ($property_type eq $SEVEN_ZIP_CREATION_TIME)
      {
        my @creation_times = get_uint64_defined_vector ($fp, $number_files);

        my $number_creation_times = scalar (@creation_times);

        for (my $i = 0; $i < $number_creation_times; $i++)
        {
          $files[$i]->{'creation_time'} = $creation_times[$i];
        }
      }
      elsif ($property_type eq $SEVEN_ZIP_ACCESS_TIME)
      {
        my @access_times = get_uint64_defined_vector ($fp, $number_files);

        my $number_access_times = scalar (@access_times);

        for (my $i = 0; $i < $number_access_times; $i++)
        {
          $files[$i]->{'access_time'} = $access_times[$i];
        }
      }
      elsif ($property_type eq $SEVEN_ZIP_MODIFICATION_TIME)
      {
        my @modification_times = get_uint64_defined_vector ($fp, $number_files);

        my $number_modification_times = scalar (@modification_times);

        for (my $i = 0; $i < $number_modification_times; $i++)
        {
          $files[$i]->{'modification_time'} = $modification_times[$i];
        }
      }
      elsif ($property_type eq $SEVEN_ZIP_DUMMY)
      {
        my $compare_bytes = "\x00" x $size;

        my $bytes = my_read ($fp, $size);

        if ($bytes ne $compare_bytes)
        {
          return undef;
        }
      }
      else
      {
        # ignore (isKnownType also in 7-Zip source code)

        my_read ($fp, $size);
      }
    }
  }

  # next id should be SEVEN_ZIP_END, but we (and 7-ZIP source code too) do not care

  my $id = read_id ($fp);

  # check anti files

  my $number_anti_items = 0;

  for (my $i = 0; $i < $number_empty_streams; $i++)
  {
    if ($anti_files[$i] != 0)
    {
      $number_anti_items++;
    }
  }

  # set digests depending on empty/anti files

  my $index_sizes = 0;
  my $index_empty_files = 0;

  my $unpack_info = $streams_info->{'unpack_info'};
  my $substreams_info = $streams_info->{'substreams_info'};

  for (my $i = 0; $i < $number_files; $i++)
  {
    my $is_anti = 0;
    my $has_stream = 1;

    if ($empty_streams[$i] == 1)
    {
      $has_stream = 0;
    }

    $files[$i]->{'has_stream'} = $has_stream;
    $files[$i]->{'crc'} = "";

    if ($has_stream == 1)
    {
      $is_anti = 0;

      $files[$i]->{'is_dir'} = 0;
      $files[$i]->{'size'} = $unpack_info->{'unpack_sizes'}[$index_sizes];

      $files[$i]->{'crc_defined'} = 0;
      $files[$i]->{'crc'} = "";

      my $is_crc_defined = has_valid_folder_crc ($unpack_info->{'digests'}, $index_sizes);

      if ($is_crc_defined == 1)
      {
        $files[$i]->{'crc_defined'} = 1;

        my $crc_item = $unpack_info->{'digests'}[$index_sizes];

        $files[$i]->{'crc'} = $crc_item->{'crc'};
      }
      else
      {
        # can we really do this too?

        $is_crc_defined = has_valid_folder_crc ($substreams_info->{'digests'}, $index_sizes);

        if ($is_crc_defined == 1)
        {
          $files[$i]->{'crc_defined'} = 1;

          my $crc_item = $substreams_info->{'digests'}[$index_sizes];

          $files[$i]->{'crc'} = $crc_item->{'crc'};
        }
      }

      $index_sizes++;
    }
    else
    {
      my $is_dir = 0;

      if ($empty_files[$index_empty_files] == 0)
      {
        $files[$i]->{'is_dir'} = 1;
      }
      else
      {
        $files[$i]->{'is_dir'} = 0;
      }

      $files[$i]->{'size'} = 0;

      $files[$i]->{'crc_defined'} = 0;
      $files[$i]->{'crc'} = "";

      $index_empty_files++;
    }
  }

  $files_info = {
    "number_files" => $number_files,
    "files" => \@files
  };

  return $files_info;
}

sub has_valid_folder_crc
{
  my $digests = shift;
  my $index   = shift;

  if (! defined (@$digests[$index]))
  {
    return 0;
  }

  my $digest = @$digests[$index];

  if ($digest->{'defined'} != 1)
  {
    return 0;
  }

  if (length ($digest->{'crc'}) < 1)
  {
    return 0;
  }

  return 1;
}

sub read_seven_zip_substreams_info
{
  my $fp = shift;

  my $unpack_info = shift;

  my $number_folders = $unpack_info->{'number_folders'};
  my $folders = $unpack_info->{'folders'};

  my $folders_digests = $unpack_info->{'digests'};

  my $substreams_info;
  my @number_unpack_streams = (1) x $number_folders;
  my @unpack_sizes;
  my @digests;

  # get the numbers of unpack streams

  my $id;

  while (1)
  {
    $id = read_id ($fp);

    if ($id eq $SEVEN_ZIP_NUM_UNPACK_STREAM)
    {
      for (my $i = 0; $i < $number_folders; $i++)
      {
        $number_unpack_streams[$i] = read_number ($fp);
      }

      next;
    }
    elsif ($id eq $SEVEN_ZIP_CRC)
    {
      last;
    }
    elsif ($id eq $SEVEN_ZIP_SIZE)
    {
      last;
    }
    elsif ($id eq $SEVEN_ZIP_END)
    {
      last;
    }

    skip_seven_zip_data ($fp);
  }

  if ($id eq $SEVEN_ZIP_SIZE)
  {
    for (my $i = 0; $i < $number_folders; $i++)
    {
      my $number_substreams = $number_unpack_streams[$i];

      if ($number_substreams == 0)
      {
        next;
      }

      my $sum_unpack_sizes = 0;

      for (my $j = 1; $j < $number_substreams; $j++)
      {
        my $size = read_number ($fp);

        push (@unpack_sizes, $size);

        $sum_unpack_sizes += $size;
      }

      # add the folder unpack size itself

      my $folder_unpack_size = get_folder_unpack_size ($unpack_info, $i);

      if ($folder_unpack_size < $sum_unpack_sizes)
      {
        return undef;
      }

      my $size = $folder_unpack_size - $sum_unpack_sizes;

      push (@unpack_sizes, $size);
    }

    $id = read_id ($fp);
  }
  else
  {
    for (my $i = 0; $i < $number_folders; $i++)
    {
      my $number_substreams = $number_unpack_streams[$i];

      if ($number_substreams > 1)
      {
        return undef;
      }

      if ($number_substreams == 1)
      {
        push (@unpack_sizes, get_folder_unpack_size ($unpack_info, $i));
      }
    }
  }

  my $number_digests = 0;

  for (my $i = 0; $i < $number_folders; $i++)
  {
    my $number_substreams = $number_unpack_streams[$i];

    if (($number_substreams != 1) || (has_valid_folder_crc ($folders_digests, $i) == 0))
    {
      $number_digests += $number_substreams;
    }
  }

  while (1)
  {
    if ($id eq $SEVEN_ZIP_END)
    {
      last;
    }
    elsif ($id eq $SEVEN_ZIP_CRC)
    {
      my @is_digest_defined = get_boolean_vector_check_all ($fp, $number_digests);

      my $k  = 0;
      my $k2 = 0;

      for (my $i = 0; $i < $number_folders; $i++)
      {
        my $number_substreams = $number_unpack_streams[$i];

        if (($number_substreams == 1) && (has_valid_folder_crc ($folders_digests, $i)))
        {
          $digests[$k]->{'defined'} = 1;
          $digests[$k]->{'crc'} = @$folders_digests[$i]->{'crc'};

          $k++;
        }
        else
        {
          for (my $j = 0; $j < $number_substreams; $j++)
          {
            my $defined = $is_digest_defined[$k2];

            # increase k2

            $k2++;

            if ($defined == 1)
            {
              my $digest = 0;

              for (my $i = 0; $i < 4; $i++)
              {
                my $val = my_read ($fp, 1);

                $val = ord ($val);

                $digest |= ($val << (8 * $i));
              }

              $digests[$k]->{'defined'} = 1;
              $digests[$k]->{'crc'} = $digest;
            }
            else
            {
              $digests[$k]->{'defined'} = 0;
              $digests[$k]->{'crc'} = 0;
            }

            $k++;
          }
        }
      }
    }
    else
    {
      skip_seven_zip_data ($fp);
    }

    $id = read_id ($fp);
  }

  my $len_defined = scalar (@digests);
  my $len_unpack_sizes = scalar (@unpack_sizes);

  if ($len_defined != $len_unpack_sizes)
  {
    my $k = 0;

    for (my $i = 0; $i < $number_folders; $i++)
    {
      my $number_substreams = $number_unpack_streams[$i];

      if (($number_substreams == 1) && (has_valid_folder_crc ($folders_digests, $i)))
      {
        $digests[$k]->{'defined'} = 1;
        $digests[$k]->{'crc'} = @$folders_digests[$i]->{'crc'};

        $k++;
      }
      else
      {
        for (my $j = 0; $j < $number_substreams; $j++)
        {
          $digests[$k]->{'defined'} = 0;
          $digests[$k]->{'crc'} = 0;

          $k++;
        }
      }
    }
  }

  $substreams_info = {
    "unpack_stream_numbers" => \@number_unpack_streams,
    "unpack_sizes" => \@unpack_sizes,
    "number_digests" => $number_digests,
    "digests" => \@digests
  };

  return $substreams_info;
}

sub has_encrypted_header
{
  my $folder = shift;

  my $encrypted;

  # get first coder

  my $coders = $folder->{'coders'};

  # get attributes of the first coder

  my $attributes = @$coders[0]->{'codec_id'};

  if ($attributes eq $SEVEN_ZIP_AES)
  {
    $encrypted = 1;
  }
  else
  {
    $encrypted = 0;
  }

  return $encrypted;
}

sub show_empty_streams_info_warning
{
  my $file_path = shift;

  print STDERR "WARNING: the file '" . $file_path . "' does not contain any meaningful data (the so-called streams info), it might only contain a list of empty files.\n";
}

sub get_folder_unpack_size
{
  my $unpack_info  = shift;
  my $folder_index = shift;

  my $index = $unpack_info->{'coder_unpack_sizes'}[$folder_index] + $unpack_info->{'main_unpack_size_index'}[$folder_index];

  return $unpack_info->{'unpack_sizes'}[$index];
}

sub get_boolean_vector
{
  my $fp = shift;

  my $number_items = shift;

  my @booleans;

  # get the values

  my $v = 0;
  my $mask = 0;

  for (my $i = 0; $i < $number_items; $i++)
  {
    if ($mask == 0)
    {
      my $byte = my_read ($fp, 1);

      $v = ord ($byte);
      $mask = 0x80;
    }

    my $val = ($v & $mask) != 0;

    push (@booleans, $val);

    $mask >>= 1;
  }

  return @booleans;
}

sub get_boolean_vector_check_all
{
  my $fp = shift;

  my $number_items = shift;

  my @booleans;

  # check first byte to see if all are defined

  my $all_defined = my_read ($fp, 1);

  if ($all_defined eq $SEVEN_ZIP_ALL_DEFINED)
  {
    @booleans = (1) x $number_items;
  }
  else
  {
    @booleans = get_boolean_vector ($fp, $number_items);
  }

  return @booleans;
}

sub read_seven_zip_digests
{
  my $fp = shift;

  my $number_items = shift;

  my @digests;

  # init

  for (my $i = 0; $i < $number_items; $i++)
  {
    my $digest = {
      "crc" => "",
      "defined" => 0
    };

    push (@digests, $digest)
  }

  # get number of items

  my @digests_defined = get_boolean_vector_check_all ($fp, $number_items);

  # for each number of item, get a digest

  for (my $i = 0; $i < $number_items; $i++)
  {
    my $crc = 0;

    for (my $i = 0; $i < 4; $i++)
    {
      my $val = my_read ($fp, 1);

      $val = ord ($val);

      $crc |= ($val << (8 * $i));
    }

    $digests[$i]->{'crc'} = $crc;
    $digests[$i]->{'defined'} = $digests_defined[$i];
  }

  return @digests;
}

sub read_seven_zip_folders
{
  my $fp = shift;

  my $folder;

  my @coders = ();
  my @bindpairs = ();
  my $index_main_stream = 0;
  my $sum_input_streams  = 0;
  my $sum_output_streams = 0;
  my $sum_packed_streams = 1;

  # NumCoders

  my $number_coders = read_number ($fp);

  # loop

  for (my $i = 0; $i < $number_coders; $i++)
  {
    my $main_byte = my_read ($fp, 1);

    $main_byte = ord ($main_byte);

    if ($main_byte & 0xC0)
    {
      return undef;
    }

    my $codec_id_size = $main_byte & 0xf;

    if ($codec_id_size > 8)
    {
      return undef;
    }

    # the codec id (very important info for us):
    # codec_id: 06F10701 -> AES-256 + SHA-256
    # codec_id: 030101   -> lzma  (we need to decompress - k_LZMA)
    # codec_id: 21       -> lzma2 (we need to decompress - k_LZMA2)

    my $codec_id = my_read ($fp, $codec_id_size);

    # NumInStreams

    my $number_input_streams = 1;

    # NumOutStreams

    my $number_output_streams = 1;

    if (($main_byte & 0x10) != 0)
    {
      $number_input_streams  = read_number ($fp);
      $number_output_streams = read_number ($fp);
    }

    $sum_input_streams  += $number_input_streams;
    $sum_output_streams += $number_output_streams;

    # attributes

    my $attributes;

    if (($main_byte & 0x020) != 0)
    {
      my $property_size = read_number ($fp);

      $attributes = my_read ($fp, $property_size);
    }

    $coders[$i] = {
      "codec_id" => $codec_id,
      "number_input_streams" => $number_input_streams,
      "number_output_streams" => $number_output_streams,
      "attributes" => $attributes
    };
  }

  if (($sum_input_streams != 1) || ($sum_output_streams != 1))
  {
    # InStreamUsed / OutStreamUsed

    my @input_stream_used  = (0) x $sum_input_streams;
    my @output_stream_used = (0) x $sum_output_streams;

    # BindPairs

    my $number_bindpairs = $sum_output_streams - 1;

    for (my $i = 0; $i < $number_bindpairs; $i++)
    {
      # input

      my $index_input = read_number ($fp);

      if ($input_stream_used[$index_input] == 1)
      {
        return undef; # the stream is used already, shouldn't happen at all
      }

      $input_stream_used[$index_input] = 1;

      # output

      my $index_output = read_number ($fp);

      if ($output_stream_used[$index_output] == 1)
      {
        return undef;
      }

      $output_stream_used[$index_output] = 1;

      my @new_bindpair = ($index_input, $index_output);

      push (@bindpairs, \@new_bindpair);
    }

    # PackedStreams

    $sum_packed_streams = $sum_input_streams - $number_bindpairs;

    if ($sum_packed_streams != 1)
    {
      for (my $i = 0; $i < $sum_packed_streams; $i++)
      {
        # we can ignore this

        read_number ($fp); # my $index = read_number ($fp);
      }
    }

    # determine the main stream

    $index_main_stream = -1;

    for (my $i = 0; $i < $sum_output_streams; $i++)
    {
      if ($output_stream_used[$i] == 0)
      {
        $index_main_stream = $i;

        last;
      }
    }

    if ($index_main_stream == -1)
    {
      return undef; # should not happen
    }
  }

  $folder = {
    "number_coders" => $number_coders,
    "coders" => \@coders,
    "bindpairs" => \@bindpairs,
    "index_main_stream"  => $index_main_stream,
    "sum_input_streams"  => $sum_input_streams,
    "sum_output_streams" => $sum_output_streams,
    "sum_packed_streams" => $sum_packed_streams,
  };

  return $folder;
}

sub read_seven_zip_unpack_info
{
  my $fp = shift;

  my $unpack_info;

  my $number_folders = 0;
  my @folders = ();
  my @datastream_indices = ();
  my @unpack_sizes;
  my @digests;
  my @main_unpack_size_index;
  my @coder_unpack_sizes;

  # check until we see the "folder" id

  if (! wait_for_seven_zip_id ($fp, $SEVEN_ZIP_FOLDER))
  {
    return undef;
  }

  # NumFolders

  $number_folders = read_number ($fp);

  # External

  my $external = my_read ($fp, 1);

  # loop

  my $sum_coders_output_streams = 0;
  my $sum_folders = 0;

  for (my $i = 0; $i < $number_folders; $i++)
  {
    if ($external eq $SEVEN_ZIP_NOT_EXTERNAL)
    {
      my $folder = read_seven_zip_folders ($fp);

      $folders[$i] = $folder;

      $main_unpack_size_index[$i] = $folder->{'index_main_stream'};
      $coder_unpack_sizes[$i] = $sum_coders_output_streams;

      $sum_coders_output_streams += $folder->{'sum_output_streams'};

      $sum_folders++;
    }
    elsif ($external eq $SEVEN_ZIP_EXTERNAL)
    {
      $datastream_indices[$i] = read_number ($fp);
    }
    else
    {
      return undef;
    }
  }

  if (!wait_for_seven_zip_id ($fp, $SEVEN_ZIP_UNPACK_SIZE))
  {
    return undef;
  }

  for (my $i = 0; $i < $sum_coders_output_streams; $i++)
  {
    $unpack_sizes[$i] = read_number ($fp);
  }

  # read remaining data

  while (1)
  {
    my $id = read_id ($fp);

    if ($id eq $SEVEN_ZIP_END)
    {
      $unpack_info = {
        "number_folders" => $number_folders,
        "folders" => \@folders,
        "datastream_indices" => \@datastream_indices,
        "digests" => \@digests,
        "unpack_sizes" => \@unpack_sizes,
        "main_unpack_size_index" => \@main_unpack_size_index,
        "coder_unpack_sizes" => \@coder_unpack_sizes
      };

      return $unpack_info;
    }
    elsif ($id eq $SEVEN_ZIP_CRC)
    {
      my @new_digests = read_seven_zip_digests ($fp, $sum_folders);

      for (my $i = 0; $i < $sum_folders; $i++)
      {
        $digests[$i]->{'defined'} = $new_digests[$i]->{'defined'};
        $digests[$i]->{'crc'} = $new_digests[$i]->{'crc'};
      }

      next;
    }

    skip_seven_zip_data ($fp);
  }

  # something went wrong

  return undef;
}

sub wait_for_seven_zip_id
{
  my $fp = shift;
  my $id = shift;

  while (1)
  {
    my $new_id = read_id ($fp);

    if ($new_id eq $id)
    {
      return 1;
    }
    elsif ($new_id eq $SEVEN_ZIP_END)
    {
      return 0;
    }

    skip_seven_zip_data ($fp);
  }

  return 0;
}

sub read_seven_zip_pack_info
{
  my $fp = shift;

  my $pack_info;

  # PackPos

  my $pack_pos = read_number ($fp);

  # NumPackStreams

  my $number_pack_streams = read_number ($fp);

  # must be "size" id

  if (! wait_for_seven_zip_id ($fp, $SEVEN_ZIP_SIZE))
  {
    return undef;
  }

  my @pack_sizes = (0) x $number_pack_streams;

  for (my $i = 0; $i < $number_pack_streams; $i++)
  {
    $pack_sizes[$i] = read_number ($fp);
  }

  $pack_info = {
    "number_pack_streams" => $number_pack_streams,
    "pack_pos" => $pack_pos,
    "pack_sizes" => \@pack_sizes
  };

  # read remaining data

  while (1)
  {
    my $id = read_id ($fp);

    if ($id eq $SEVEN_ZIP_END)
    {
      return $pack_info;
    }
    elsif ($id eq $SEVEN_ZIP_CRC)
    {
      my $digests = read_seven_zip_digests ($fp, $number_pack_streams);

      # we do not need those digests, ignore them
      # (but we need to read them from the stream)

      next;
    }

    skip_seven_zip_data ($fp);
  }

  # something went wrong

  return undef;
}

sub read_seven_zip_streams_info
{
  my $fp = shift;

  my $streams_info;

  my $pack_info;
  my $unpack_info;
  my $substreams_info;

  # get the type of streams info (id)

  my $id = read_id ($fp);

  if ($id eq $SEVEN_ZIP_PACK_INFO)
  {
    $pack_info = read_seven_zip_pack_info ($fp);

    return undef unless (defined ($pack_info));

    $id = read_id ($fp);
  }

  if ($id eq $SEVEN_ZIP_UNPACK_INFO)
  {
    $unpack_info = read_seven_zip_unpack_info ($fp);

    return undef unless (defined ($unpack_info));

    $id = read_id ($fp);
  }

  if ($id eq $SEVEN_ZIP_SUBSTREAMS_INFO)
  {
    $substreams_info = read_seven_zip_substreams_info ($fp, $unpack_info);

    return undef unless (defined ($substreams_info));

    $id = read_id ($fp);
  }
  else
  {
    my @number_unpack_streams = ();
    my @unpack_sizes = ();
    my $number_digests = 0;
    my $digests;

    if (defined ($unpack_info))
    {
      my $folders = $unpack_info->{'folders'};

      my $number_folders = $unpack_info->{'number_folders'};

      for (my $i = 0; $i < $number_folders; $i++)
      {
        $number_unpack_streams[$i] = 1;

        my $folder_unpack_size = get_folder_unpack_size ($unpack_info, $i);

        push (@unpack_sizes, $folder_unpack_size);
      }
    }

    $substreams_info = {
      "unpack_stream_numbers" => \@number_unpack_streams,
      "unpack_sizes" => \@unpack_sizes,
      "number_digests" => $number_digests,
      "digests" => $digests
    };
  }

  $streams_info = {
    "pack_info" => $pack_info,
    "unpack_info" => $unpack_info,
    "substreams_info" => $substreams_info
  };

  return $streams_info;
}

sub read_and_decode_seven_zip_packed_stream
{
  my $fp = shift;

  my $packed_stream;

  $packed_stream = read_seven_zip_streams_info ($fp);

  # for each folder, get the decoder and decode the data

  return $packed_stream;
}

sub num_to_id
{
  my $num = shift;

  # special case:

  return "\x00" if ($num == 0);

  # normal case:

  my $id = "";

  while ($num > 0)
  {
    my $value = $num & 0xff;

    $id = chr ($value) . $id;

    $num >>= 8;
  }

  return $id;
}

sub read_number
{
  my $fp = shift;

  my $b = ord (my_read ($fp, 1));

  if (($b & 0x80) == 0)
  {
    return $b;
  }

  my $value = ord (my_read ($fp, 1));

  for (my $i = 1; $i < 8; $i++)
  {
    my $mask = 0x80 >> $i;

    if (($b & $mask) == 0)
    {
      my $high = $b & ($mask - 1);

      $value |= ($high << ($i * 8));

      return $value;
    }

    my $next = ord (my_read ($fp, 1));

    $value |= ($next << ($i * 8));
  }

  return $value;
}

sub read_id
{
  my $fp = shift;

  my $id;

  my $num = read_number ($fp);

  # convert number to their ASCII code correspondent byte

  return num_to_id ($num);
}

sub is_supported_seven_zip_file
{
  my $fp = shift;

  my $magic_len = length ($SEVEN_ZIP_MAGIC);

  my $signature = my_read ($fp, $magic_len);

  return $signature eq $SEVEN_ZIP_MAGIC;
}

sub read_seven_zip_header
{
  my $fp = shift;

  my $header;

  my $additional_streams_info;
  my $streams_info;
  my $files_info;

  # get the type of header

  my $id = read_id ($fp);

  if ($id eq $SEVEN_ZIP_ARCHIVE_PROPERTIES)
  {
    # we just ignore the data here (but we need to read it from the stream!)

    if (! read_seven_zip_archive_properties ($fp))
    {
      return undef;
    }

    $id = read_id ($fp);
  }

  if ($id eq $SEVEN_ZIP_ADD_STREAMS_INFO)
  {
    $additional_streams_info = read_and_decode_seven_zip_packed_stream ($fp);

    return undef unless (defined ($additional_streams_info));

    # do we need to change the start position here ?

    $id = read_id ($fp);
  }

  if ($id eq $SEVEN_ZIP_MAIN_STREAMS_INFO)
  {
    $streams_info = read_seven_zip_streams_info ($fp);

    return undef unless (defined ($streams_info));

    $id = read_id ($fp);
  }

  if ($id eq $SEVEN_ZIP_FILES_INFO)
  {
    $files_info = read_seven_zip_files_info ($fp, $streams_info);

    return undef unless (defined ($files_info));
  }

  $header = {
    "additional_streams_info" => $additional_streams_info,
    "streams_info" => $streams_info,
    "files_info" => $files_info,
    "type" => "raw"
  };

  return $header;
}

sub parse_seven_zip_header
{
  my $fp = shift;

  my $header;
  my $streams_info;

  # get the type of the header (id)

  my $id = read_id ($fp);

  # check if either encoded/packed or encrypted: to get the details we need to check the method

  if ($id ne $SEVEN_ZIP_HEADER)
  {
    if ($id ne $SEVEN_ZIP_ENCODED_HEADER)
    {
      # when we reach this code section we probably found an invalid 7z file (just ignore it!)
      # print STDERR "WARNING: only encoded headers are allowed if no raw header is present\n";

      return undef;
    }

    $streams_info = read_and_decode_seven_zip_packed_stream ($fp);

    return undef unless (defined ($streams_info));

    $header = {
      "additional_streams_info" => undef,
      "streams_info" => $streams_info,
      "files_info" => undef,
      "type" => "encoded"
    }

    # Note: now the 7-Zip code normally parses the header (which we got from the decode operation above)
    # but we do not really need to do this here. Skip
  }
  else
  {
    $header = read_seven_zip_header ($fp);

    # special case (set attribute s.t. we know we have to show a warning):

    $header->{'no_header_encryption'} = 1;
  }

  return $header;
}

sub read_seven_zip_next_header
{
  my $fp = shift;

  my $header_size   = shift;
  my $header_offset = shift;

  my $header;

  # get the header of size header_size at relative position header_offset

  my_seek ($fp, $header_offset, 1);

  # read the header

  $header = parse_seven_zip_header ($fp);

  return $header;
}

sub my_seek
{
  my $input  = shift;
  my $offset = shift;
  my $whence = shift;

  my $res = 0;

  my $type_of_input = ref ($input);

  if ($type_of_input eq "HASH")
  {
    # get total number of files and total/accumulated file size

    my $number_of_files= 1;

    # we assume that $$input{1} exists (we did already check that beforehand)

    my $end = 0;

    while (exists ($$input{$number_of_files}))
    {
      $end = $$input{$number_of_files}{'start'} + $$input{$number_of_files}{'size'};

      $number_of_files++;
    }

    my $new_offset = 0;

    # absolute (from start)
    if ($whence == 0)
    {
      $new_offset = $offset;
    }
    # relative (depending on current position)
    elsif ($whence == 1)
    {
      $new_offset = $memory_buffer_read_offset + $offset;
    }
    # offset from the end of the file
    else
    {
      $new_offset = $end + $offset;
    }

    # sanity check

    if (($new_offset < 0) || ($new_offset > $end))
    {
      my $name = get_splitted_archive_raw_name ($$input{1}{'name'});

      print STDERR "ERROR: could not seek within the splitted archive '$name'\n";

      exit (1);
    }

    $memory_buffer_read_offset = $new_offset;

    # check if the correct file is open
    # 1. determine the correct file
    # 2. if the "incorrect" file is open, close it and open the correct one

    my $cur_file_number = 1;
    my $file_was_found  = 0;

    my $start = 0;
    my $size  = 0;

    while (exists ($$input{$cur_file_number}))
    {
      $start = $$input{$cur_file_number}{'start'};
      $size  = $$input{$cur_file_number}{'size'};

      my $end = $start + $size;

      if ($memory_buffer_read_offset >= $start)
      {
        if ($memory_buffer_read_offset < $end)
        {
          $file_was_found = 1;

          last;
        }
      }

      $cur_file_number++;
    }

    if ($file_was_found == 0)
    {
      my $name = get_splitted_archive_raw_name ($$input{1}{'name'});

      print STDERR "ERROR: could not read the splitted archive '$name' (maybe some parts are missing?)\n";

      exit (1);
    }

    if ($$input{0}{'num'} != $cur_file_number)
    {
      # if we enter this block, we definitely need to "change" to another file

      close ($$input{0}{'fh'});

      my $name = $$input{$cur_file_number}{'name'};

      my $seven_zip_file;

      if (! open ($seven_zip_file, "<$name"))
      {
        print STDERR "ERROR: could not open the file '$name' for reading\n";

        exit (1);
      }

      $$input{0}{'fh'}  = $seven_zip_file;
      $$input{0}{'num'} = $cur_file_number;
    }

    # always seek w/ absolute positions within the splitted part!
    $res = seek ($$input{0}{'fh'}, $memory_buffer_read_offset - $start, 0);
  }
  else
  {
    $res = seek ($input, $offset, $whence);
  }

  return $res;
}

sub my_tell
{
  my $input = shift;

  my $res = 0;

  my $type_of_input = ref ($input);

  if ($type_of_input eq "HASH")
  {
    $res = $memory_buffer_read_offset;
  }
  else
  {
    $res = tell ($input);
  }

  return $res;
}

sub get_uint64
{
  my $fp = shift;

  my $bytes = my_read ($fp, 8);

  return (0, 0) if (length ($bytes) != 8);

  my ($uint1, $uint2) = unpack ("LL<", $bytes);

  my $num = $uint2 << 32 | $uint1;

  return $bytes, $num;
}

sub read_seven_zip_signature_header
{
  my $fp = shift;

  my $signature;

  # ArchiveVersion

  my $major_version = my_read ($fp, 1);

  $major_version = ord ($major_version);

  my $minor_version = my_read ($fp, 1);

  $minor_version = ord ($minor_version);

  # StartHeaderCRC

  my_read ($fp, 4); # skip start header CRC

  # StartHeader

  my $next_header_offset = get_uint64 ($fp);
  my $next_header_size   = get_uint64 ($fp);

  my_read ($fp, 4); # next header CRC

  my $position_after_header = my_tell ($fp);

  $signature = {
    "major_version" => $major_version,
    "minor_version" => $minor_version,
    "next_header_offset" => $next_header_offset,
    "next_header_size" => $next_header_size,
    "position_after_header" => $position_after_header
  };

  return $signature;
}

sub read_seven_zip_archive
{
  my $fp = shift;

  my $archive;

  # SignatureHeader

  my $signature = read_seven_zip_signature_header ($fp);

  return undef unless (defined ($signature));

  # parse the header

  my $parsed_header = read_seven_zip_next_header ($fp, $signature->{'next_header_size'}, $signature->{'next_header_offset'});

  return undef unless (defined ($parsed_header));

  $archive = {
    "signature_header" => $signature,
    "parsed_header" => $parsed_header
  };

  return $archive;
}

sub strip_header_encryption_pass
{
  my $fp               = shift;
  my $archive          = shift;
  my $file_path        = shift;
  my $header_pass      = shift;
  my $output_file_name = shift;

  return unless (defined ($archive));

  my $parsed_header = $archive->{'parsed_header'};
  return unless (defined ($parsed_header));

  if (defined ($archive->{'parsed_header'}->{'no_header_encryption'}))
  {
    print STDERR "ERROR: The file '$file_path' does not use header encryption.\n";

    return;
  }

  my $signature_header = $archive->{'signature_header'};
  return unless (defined ($signature_header));

  my $streams_info = $parsed_header->{'streams_info'};

  if (! defined ($streams_info))
  {
    show_empty_streams_info_warning ($file_path);

    return;
  }

  my $unpack_info = $streams_info->{'unpack_info'};
  return unless (defined ($unpack_info));

  my $substreams_info = $streams_info->{'substreams_info'};

  my $digests = $unpack_info->{'digests'};
  return unless (defined ($digests));

  my $folders = $unpack_info->{'folders'};
  return unless (defined ($folders));

  my $pack_info = $streams_info->{'pack_info'};
  return unless (defined ($pack_info));

  # init file seek values

  my $position_after_header = $signature_header->{'position_after_header'};
  my $position_pack = $pack_info->{'pack_pos'};
  my $current_seek_position = $position_after_header + $position_pack;


  #
  # start:
  #

  # get first folder/coder

  my $folder_id = 0;

  my $folder = @$folders[$folder_id];

  my $number_coders = $folder->{'number_coders'};

  # check if header is encrypted

  my $has_encrypted_header = 0;

  if ($number_coders > 1)
  {
    $has_encrypted_header = 0;
  }
  else
  {
    $has_encrypted_header = has_encrypted_header ($folder);
  }

  # get the first coder

  my $coder_index = 0;

  my $coder = $folder->{'coders'}[$coder_index];
  return unless (defined ($coder));

  my $codec_id = $coder->{'codec_id'};

  # set index and seek to postition

  my $pack_size_index   = 0;
  my $unpack_size_index = 0;
  my $folder_index      = 0;

  my_seek ($fp, $current_seek_position, 0);


  if ($codec_id ne $SEVEN_ZIP_AES) # encrypted header encryption
  {
    print STDERR "WARNING: unsupported coder with codec id '0x" . unpack ("H*", $codec_id) . "' in file '" . $file_path . "' found.\n";

    return;
  }


  #
  # finally: decrypt the header/data
  #

  my $unpack_size = get_folder_aes_unpack_size ($unpack_info, $folder_index);

  my $data_len = $pack_info->{'pack_sizes'}[$pack_size_index];

  # reset the file pointer to the position after signature header and get the data

  my_seek ($fp, $current_seek_position, 0);

  # get remaining hash info (iv, number cycles power)

  my $digest = get_digest ($unpack_size_index, $unpack_info, $substreams_info);

  return "" unless ((defined ($digest)) && ($digest->{'defined'} == 1));

  my $attributes = $coder->{'attributes'};

  my ($salt_len, $salt_buf, $iv_len, $iv_buf, $number_cycles_power) = get_decoder_properties ($attributes);

  my $crc = $digest->{'crc'};

  my @coder_attributes = (); # type, is_preprocessor, attributes

  for (my $coder_pos = $coder_index + 1; $coder_pos < $number_coders; $coder_pos++)
  {
    $coder = $folder->{'coders'}[$coder_pos];
    last unless (defined ($coder));

    my $is_error = fill_additional_attribute_list (\$coder, $file_path, \@coder_attributes);

    return if ($is_error == 1);
  }

  my $is_truncated = 0;
  my $padding_attack_possible = 0;

  my ($type_of_data,
      $additional_attributes,
      $codec_warning_shown,
      $attribute_error) = check_attributes (\@coder_attributes,
                                            $is_truncated,
                                            $file_path,
                                            $padding_attack_possible,
                                            $data_len,
                                            0);

  return if ($attribute_error == 1);

  if (($type_of_data != 0) &&
      ($type_of_data != 1))
  {
    print STDERR "ERROR: The file '$file_path' uses a compression algorithm NOT currently supported by this tool to decrypt the encrypted header (file list etc)\n";

    return;
  }

  my $crc_len = 0;

  if (($type_of_data != $SEVEN_ZIP_UNCOMPRESSED) && ($type_of_data != $SEVEN_ZIP_TRUNCATED))
  {
    if (scalar ($substreams_info->{'unpack_sizes'}) > $unpack_size_index)
    {
      $crc_len = $substreams_info->{'unpack_sizes'}[$unpack_size_index];
    }
  }

  my $data = my_read ($fp, $data_len); # NOTE: we shouldn't read a very huge data buffer directly into memory


  # 7z2hashcat output (iter, salt_len, salt, crc, data_len, unpack_size, data):
  # 19
  # 8
  # fd57beef0b24c5090000000000000000
  # 2773639980
  # 96
  # 90
  # 5121f97f8a26ed9a7321d249c123f271138d2be3191650ba7a2d563acc173c2aca515a6f198dda791727f76fa600d4e3fa0645f0c31c011ab17920bd1caedf5547b2d3eb0115b4b363ac2df12f057ebcfeb88939393b2486704dc62f6726d627

  # print STDERR $number_cycles_power   . "\n";
  # print STDERR $iv_len                . "\n";
  # print STDERR unpack ("H*", $iv_buf) . "\n";
  # print STDERR $crc                   . "\n";
  # print STDERR $data_len              . "\n";
  # print STDERR $unpack_size           . "\n";
  # print STDERR unpack ("H*", $data)   . "\n";
  # print STDERR $crc_len               . "\n";
  # print STDERR $additional_attributes . "\n";

  # some code similar to hashcat/tools/test_modules/m11600.pm

  #
  # Key derivation from password (=> AES key)
  #

  my $key = aes_derive_key ($header_pass, $number_cycles_power);


  #
  # AES decrypt:
  #

  my $aes = aes_init_context ($key, $iv_buf, $iv_len);


  #
  # Start decryption
  #

  my $decrypted_header = $aes->decrypt ($data);

  $decrypted_header = substr ($decrypted_header, 0, $unpack_size);

  my $crc_computed = 0;

  if ($type_of_data == 0)
  {
    $crc_computed = crc32 ($decrypted_header);
  }
  elsif ($type_of_data == 1)
  {
    my $lz = new Compress::Raw::Lzma::AloneDecoder (AppendOutput => 1);

    my $attributes = pack ("H*", $additional_attributes);
    my ($property_lclppb, $dict_size, $lc, $pb, $lp) = lzma_properties_decode ($attributes);

    return unless (length ($property_lclppb) == 1);

    my $dict_size_encoded         = lzma_alone_header_field_encode ($dict_size, 4); # 4 bytes (the "Dictionary Size" field), little endian
    my $uncompressed_size_encoded = lzma_alone_header_field_encode ($crc_len,   8); # 8 bytes (the "Uncompressed Size" field), little endian

    # ALTERNATIVE would be:
    # my $dict_size_encoded         = pack ("H*", "00008000");         # "default" dictionary size (2^23 = 0x00800000)
    # my $uncompressed_size_encoded = pack ("H*", "ffffffffffffffff"); # means: unknown uncompressed size

    my $lzma_alone_format_header = $property_lclppb . $dict_size_encoded . $uncompressed_size_encoded;

    my $lzma_header = $lzma_alone_format_header . $decrypted_header;

    my $decompressed_header = "";

    my $status = $lz->code ($lzma_header, $decompressed_header);

    if ((length ($status) > 0) && ($status != LZMA_STREAM_END))
    {
      print STDERR "ERROR: Could not decompress the header of file '$file_path' with LZMA1. Error: '$status'. Wrong password ?\n";

      return;
    }

    if (length ($decompressed_header) < $crc_len)
    {
      print STDERR "ERROR: The output of the decompressed header of file '$file_path' is too short. Wrong password ?\n";

      return;
    }

    $decompressed_header = substr ($decompressed_header, 0, $crc_len);

    $crc_computed = crc32 ($decompressed_header);


    # a little hack (re-use variable, just overwrite it):

    $decrypted_header = $decompressed_header;
  }
  else
  {
    print STDERR "ERROR: Unsupported data type for file '$file_path'.\n";

    return;
  }

  if ($crc_computed ne $crc)
  {
    print STDERR "ERROR: Wrong password for 7-Zip file '$file_path'\n";

    return;
  }


  my $header_id = read_id (\$decrypted_header);

  return unless ($header_id eq $SEVEN_ZIP_HEADER);

  my $header_analysis = read_seven_zip_header (\$decrypted_header);
  return unless (defined ($header_analysis));



  # get the encrypted data buffer:

  my_seek ($fp, $position_after_header, 0);

  my $encrypted_data = my_read ($fp, $position_pack); # NOTE: we shouldn't read a very huge data buffer directly into memory

  # to see the decrypted data (with the exact same password use this), use this:
  # my $second_layer_pass = $header_pass; # to test different pass, use string like "password"
  # my $key2 = aes_derive_key   ($second_layer_pass, $number_cycles_power);
  # my $aes2 = aes_init_context ($key2, $iv_buf, $iv_len);

  # my $decrypted_data = $aes2->decrypt ($encrypted_data);
  # print STDERR "\n\ndecryped data: " . unpack ("H*", $decrypted_data) . "\n\n\n";


  #
  # Finally: generate the new output file
  #

  # note that some code is similar to hc_to_7z.pl, check out that tool it's interesting too

  my $signature_header_mod;

  $signature_header_mod->{'major_version'}         = $signature_header->{'major_version'};
  $signature_header_mod->{'minor_version'}         = $signature_header->{'minor_version'};
  $signature_header_mod->{'position_after_header'} = $SEVEN_ZIP_SIGNATURE_LEN;
  $signature_header_mod->{'next_header_offset'}    = $position_pack;
  $signature_header_mod->{'next_header_size'}      = length ($decrypted_header);

  my $file_signature_mod = seven_zip_signature_header ($signature_header_mod, $crc);

  my $file_data = "";

  $file_data .= $SEVEN_ZIP_MAGIC;
  $file_data .= $file_signature_mod;
  $file_data .= $encrypted_data;
  $file_data .= $decrypted_header;


  # find out if the output file name already exists (otherwise add a number to it):

  my $output_file_name_base = $SEVEN_ZIP_OUTPUT_NAME;

  if (defined ($output_file_name))
  {
    $output_file_name_base = $output_file_name;

    $output_file_name_base =~ s/[\.]7z$//;
  }

  my $output_file_path = $output_file_name_base . $SEVEN_ZIP_FILE_EXTENSION;

  my $cur_try = 0;

  while (-e "$output_file_path")
  {
    if ($cur_try >= $SEVEN_ZIP_OUTPUT_NAME_MAX_TRIES)
    {
      print STDERR "WARNING: Too many similar output files found. Skipping file '$file_path'\n";

      return;
    }

    print STDERR "WARNING: Output file '$output_file_path' does already exist\n";

    $cur_try++;

    $output_file_path = $output_file_name_base . "_" . ($cur_try + 1) . $SEVEN_ZIP_FILE_EXTENSION;
  }


  # write to file:

  write_output_file ($file_data, $output_file_path);
}

sub seven_zip_strip_header_encryption
{
  my $file_path        = shift;
  my $pass             = shift;
  my $output_file_name = shift;

  # open file for reading

  my $seven_zip_file;

  if (! open ($seven_zip_file, "<$file_path"))
  {
    print STDERR "WARNING: could not open the file '$file_path' for reading\n";

    return -1;
  }

  binmode ($seven_zip_file);

  # check if valid and supported 7z file

  if (! is_supported_seven_zip_file ($seven_zip_file))
  {
    print STDERR "WARNING: the file '$file_path' is not a supported 7-Zip file\n";

    close ($seven_zip_file);

    return -1;
  }

  my $archive = read_seven_zip_archive ($seven_zip_file);

  strip_header_encryption_pass ($seven_zip_file, $archive, $file_path, $pass, $output_file_name);

  # cleanup

  close ($seven_zip_file);

  return 0;
}


#
# Start
#

my @file_parameters = ();
my $header_encryption_pass     = undef;
my $header_encryption_pass_pos = undef;
my $output_file_name           = undef;

for (my $i = 0; $i < scalar (@ARGV); $i++)
{
  if (($ARGV[$i] eq "-h") or
      ($ARGV[$i] eq "--help"))
  {
    usage ($0);

    exit (0);
  }
  elsif (($ARGV[$i] eq "-v") or
         ($ARGV[$i] eq "--version"))
  {
    print "$TOOL_NAME $TOOL_VERSION\n";

    exit (0);
  }
  elsif ($ARGV[$i] =~ m/^-p.+$/)
  {
    $header_encryption_pass = $ARGV[$i];

    $header_encryption_pass =~ s/^-p//;

    $header_encryption_pass_pos = $i;
  }
  elsif (($ARGV[$i] eq "--password") or
         ($ARGV[$i] eq "-p"))
  {
    if (scalar (@ARGV) gt $i)
    {
      $i++;

      $header_encryption_pass = $ARGV[$i];
    }

    $header_encryption_pass_pos = $i;
  }
  elsif ($ARGV[$i] =~ m/^-o.+$/)
  {
    $output_file_name = $ARGV[$i];

    $output_file_name =~ s/^-o//;
  }
  elsif (($ARGV[$i] eq "--output") or
         ($ARGV[$i] eq "-o"))
  {
    if (scalar (@ARGV) gt $i)
    {
      $i++;

      $output_file_name = $ARGV[$i];
    }
    else
    {
      print STDERR "ERROR: the output file name is missing\n";

      exit (1);
    }
  }
  else
  {
    push (@file_parameters, $ARGV[$i]);
  }
}

if (! defined ($header_encryption_pass_pos))
{
  print STDERR "ERROR: the password is missing in your command\n\n";

  usage ($0);

  exit (1);
}

if (scalar (@file_parameters) lt 1)
{
  if (defined ($header_encryption_pass_pos))
  {
    push (@file_parameters, $header_encryption_pass);

    $header_encryption_pass = undef;
  }
  else
  {
    print STDERR "ERROR: the path to the 7-Zip file is missing in your command\n\n";

    usage ($0);

    exit (1);
  }
}

if (! defined ($header_encryption_pass))
{
  print STDERR "Enter password: ";

  $header_encryption_pass = <STDIN>;

  $header_encryption_pass =~ s/[\r\n]$//;
}

# note: here we could also pre-compute the AES key, derived from $header_encryption_pass,
# already, if and only if we assume that $number_cycles_power is always the default and
# the same value (1 << 19 for instance) !
# i.e. pre-compute $key such that we only need to do the data decryption (depending
# also on a random IV) later on
# that strategy would give us a huge advantage especially if we have multiple files with
# the exact same password
# see "Key derivation from password (=> AES key) strip_header_encryption_pass ()


my @file_list = globbing_on_windows (@file_parameters);

my $exit_code = 0;

# iterate through the file list:

foreach my $file_name (@file_list)
{
  if (! -e $file_name)
  {
    print STDERR "WARNING: could not open file '$file_name'\n";

    next;
  }

  $memory_buffer_read_offset = 0;

  my $ret = seven_zip_strip_header_encryption ($file_name, $header_encryption_pass, $output_file_name);

  if ($ret != 0)
  {
    $exit_code = -1;
  }
}

exit ($exit_code);
