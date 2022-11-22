/*
 * IPFIX Concentrator Module Library
 * Copyright (C) 2004 Christoph Sommer <http://www.deltadevelopment.de/users/christoph/ipfix/>
 * Copyright (C) 2014 Oliver Gasser
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include "IpfixPrinter.hpp"
#include "common/Time.h"
#include "common/Misc.h"
#include "Connection.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <inttypes.h>

/**
 * print functions which have formerly been in IpfixParser.cpp
 */

void PrintHelpers::printIPv4(uint32_t data) {
	fprintf(fh, "%s", IPToString(data).c_str());
}


void PrintHelpers::printIPv4(InformationElement::IeInfo type, IpfixRecord::Data* data) {
	int octet1 = 0;
	int octet2 = 0;
	int octet3 = 0;
	int octet4 = 0;
	int imask = 0;
	if (type.length >= 1) octet1 = data[0];
	if (type.length >= 2) octet2 = data[1];
	if (type.length >= 3) octet3 = data[2];
	if (type.length >= 4) octet4 = data[3];
	if (type.length >= 5) imask = data[4];
	if (type.length > 5) {
		DPRINTF("IPv4 Address with length %u unparseable\n", type.length);
		return;
	}

	if (type.length == 5 /*&& (imask != 0)*/) {
		fprintf(fh, "%u.%u.%u.%u/%u", octet1, octet2, octet3, octet4, 32-imask);
	} else {
		fprintf(fh, "%u.%u.%u.%u", octet1, octet2, octet3, octet4);
	}
}

void PrintHelpers::reverse(unsigned short* b){
	unsigned short ret = 0;		//return value
	unsigned char bak = 0;		//backup value
	unsigned char* cur = 0;		//pointer for accessing bits
	cur = (unsigned char*) b;
	bak = *b;
	*cur = *(cur + 1);
	*((unsigned char*)(cur + 1)) = bak;
	return;
}

void PrintHelpers::printIPv6(InformationElement::IeInfo type, IpfixRecord::Data* data) {
	unsigned short part0 = 0;
	unsigned short part1 = 0;
	unsigned short part2 = 0;
	unsigned short part3 = 0;
	unsigned short part4 = 0;
	unsigned short part5 = 0;
	unsigned short part6 = 0;
	unsigned short part7 = 0;
	unsigned short imask = 0;
	if (type.length >= 1) part0 = data[0];
	if (type.length >= 2) part1 = data[1];
	if (type.length >= 3) part2 = data[2];
	if (type.length >= 4) part3 = data[3];
	if (type.length >= 5) part4 = data[4];
	if (type.length >= 6) part5 = data[5];
	if (type.length >= 7) part6 = data[6];
	if (type.length >= 8) part7 = data[7];
	if (type.length >= 9) imask = data[8];
	if (type.length > 9) {
		DPRINTF("IPv6 Address with length %u unparseable\n", type.length);
		return;
	}

	if (type.length == 9 /*&& (imask != 0)*/) {
		fprintf(fh, "%x:%x:%x:%x:%x:%x:%x:%x/%u", part0, part1, part2, part3, part4, part5, part6, part7, 32-imask);
	} else {
		fprintf(fh, "%x:%x:%x:%x:%x:%x:%x:%x", part0, part1, part2, part3, part4, part5, part6, part7);
	}
}

void PrintHelpers::printPort(InformationElement::IeInfo type, IpfixRecord::Data* data) {
	if (type.length == 0) {
		fprintf(fh, "zero-length Port");
		return;
	}
	if (type.length == 2) {
		int port = ((uint16_t)data[0] << 8)+data[1];
		fprintf(fh, "%u", port);
		return;
	}
	if ((type.length >= 4) && ((type.length % 4) == 0)) {
		int i;
		for (i = 0; i < type.length; i+=4) {
			int starti = ((uint16_t)data[i+0] << 8)+data[i+1];
			int endi = ((uint16_t)data[i+2] << 8)+data[i+3];
			if (i > 0) fprintf(fh, ",");
			if (starti != endi) {
				fprintf(fh, "%u:%u", starti, endi);
			} else {
				fprintf(fh, "%u", starti);
			}
		}
		return;
	}

	fprintf(fh, "Port with length %u unparseable", type.length);
}

void PrintHelpers::printProtocol(uint8_t data) {
	switch (data) {
	case IPFIX_protocolIdentifier_ICMP:
		fprintf(fh, "ICMP");
		return;
	case IPFIX_protocolIdentifier_TCP:
		fprintf(fh, "TCP");
		return;
	case IPFIX_protocolIdentifier_UDP:
		fprintf(fh, "UDP");
		return;
	case IPFIX_protocolIdentifier_SCTP:
		fprintf(fh, "SCTP");
		return;
	case IPFIX_protocolIdentifier_RAW:
		fprintf(fh, "RAW");
		return;
	default:
		fprintf(fh, "%u", data);
		return;
	}
}


void PrintHelpers::printProtocol(InformationElement::IeInfo type, IpfixRecord::Data* data) {
	if (type.length != 1) {
		fprintf(fh, "Protocol with length %u unparseable", type.length);
		return;
	}
	switch (data[0]) {
	case IPFIX_protocolIdentifier_ICMP:
		fprintf(fh, "ICMP");
		return;
	case IPFIX_protocolIdentifier_TCP:
		fprintf(fh, "TCP");
		return;
	case IPFIX_protocolIdentifier_UDP:
		fprintf(fh, "UDP");
		return;
	case IPFIX_protocolIdentifier_SCTP:
		fprintf(fh, "SCTP");
		return;
	case IPFIX_protocolIdentifier_RAW:
		fprintf(fh, "RAW");
		return;
	default:
		fprintf(fh, "%u", data[0]);
		return;
	}
}

void PrintHelpers::printUint(InformationElement::IeInfo type, IpfixRecord::Data* data) {
	switch (type.length) {
	case 1:
		fprintf(fh, "%hhu",*(uint8_t*)data);
		return;
	case 2:
		fprintf(fh, "%hu",ntohs(*(uint16_t*)data));
		return;
	case 4:
		fprintf(fh, "%u",ntohl(*(uint32_t*)data));
		return;
	case 8:
		fprintf(fh, "%llu",(long long unsigned)ntohll(*(uint64_t*)data));
		return;
	default:
		for(uint16_t i = 0; i < type.length; i++) {
		    fprintf(fh, "%02hhX",*(uint8_t*)(data+i));
		}
		fprintf(fh, " (%u bytes)", type.length);
		//msg(MSG_ERROR, "Uint with length %u unparseable", type.length);
		return;
	}
}


void PrintHelpers::printLocaltime(InformationElement::IeInfo type, IpfixRecord::Data* data) {
	time_t tmp;
	char str[26]; // our own buffer to be thread-proof
	switch (type.length) {
	case 1:
		fprintf(fh, "%hhu",*(uint8_t*)data);
		return;
	case 2:
		fprintf(fh, "%hu",ntohs(*(uint16_t*)data));
		return;
	case 4:
		tmp = (time_t)ntohl(*(uint32_t*)data);
		ctime_r(&tmp, str);
		// remove new line
		str[24] = '\0';
		fprintf(fh, "%u (%s)", (uint32_t)tmp, str);
		return;
	case 8:
		// we expect 8 byte timestamps to be milliseconds
		tmp = (time_t)(ntohll(*(uint64_t*)data) / 1000);
		ctime_r(&tmp, str);
		// remove new line
		str[24] = '\0';
		fprintf(fh, "%llu (%s)", (long long unsigned)ntohll(*(uint64_t*)data), str);
		return;
	default:
		for(uint16_t i = 0; i < type.length; i++) {
		    fprintf(fh, "%02hhX",*(uint8_t*)(data+i));
		}
		fprintf(fh, " (%u bytes)", type.length);
		//msg(MSG_ERROR, "Uint with length %u unparseable", type.length);
		return;
	}
}


void PrintHelpers::printUint(char* buf, InformationElement::IeInfo type, IpfixRecord::Data* data) {
	switch (type.length) {
	case 1:
		sprintf(buf, "%hhu",*(uint8_t*)data);
		return;
	case 2:
		sprintf(buf, "%hu",ntohs(*(uint16_t*)data));
		return;
	case 4:
		sprintf(buf, "%u",ntohl(*(uint32_t*)data));
		return;
	case 8:
		sprintf(buf, "%llu",(long long unsigned)ntohll(*(uint64_t*)data));
		return;
	default:
		msg(MSG_ERROR, "Uint with length %u unparseable", type.length);
		return;
	}
}


/**
 * Prints a string representation of IpfixRecord::Data to stdout.
 */
void PrintHelpers::printFieldData(InformationElement::IeInfo type, IpfixRecord::Data* pattern) {

	timeval t;
	uint64_t hbnum;
	string typeStr = type.toString();

	// try to get the values aligned
	if (typeStr.length() < 60)
		fprintf(fh, "%-60s: ", type.toString().c_str());
	else
		fprintf(fh, "%s: ", type.toString().c_str());

	switch (type.enterprise) {
		case 0:
			switch (type.id) {
				case IPFIX_TYPEID_protocolIdentifier:
					printProtocol(type, pattern);
					return;
				case IPFIX_TYPEID_sourceIPv4Address:
					printIPv4(type, pattern);
					return;
				case IPFIX_TYPEID_destinationIPv4Address:
					printIPv4(type, pattern);
					return;
				case IPFIX_TYPEID_sourceIPv6Address:
					printIPv6(type, pattern);
					return;
				case IPFIX_TYPEID_destinationIPv6Address:
					printIPv6(type, pattern);
					return;
				case IPFIX_TYPEID_sourceTransportPort:
					printPort(type, pattern);
					return;
				case IPFIX_TYPEID_destinationTransportPort:
					printPort(type, pattern);
					return;
				case IPFIX_TYPEID_flowStartSeconds:
				case IPFIX_TYPEID_flowEndSeconds:
				case IPFIX_TYPEID_flowStartMilliseconds:
				case IPFIX_TYPEID_flowEndMilliseconds:
				case PSAMP_TYPEID_observationTimeSeconds:
					printLocaltime(type, pattern);
					return;
				case IPFIX_TYPEID_flowStartNanoseconds:
				case IPFIX_TYPEID_flowEndNanoseconds:
					hbnum = ntohll(*(uint64_t*)pattern);
					if (hbnum>0) {
						t = timentp64(*((ntp64*)(&hbnum)));
						fprintf(fh, "%u.%06d seconds", (int32_t)t.tv_sec, (int32_t)t.tv_usec);
					} else {
						fprintf(fh, "no value (only zeroes in field)");
					}
					return;
			}
			break;

		case IPFIX_PEN_reverse:
			switch (type.id) {
				case IPFIX_TYPEID_flowStartSeconds:
				case IPFIX_TYPEID_flowEndSeconds:
				case IPFIX_TYPEID_flowStartMilliseconds:
				case IPFIX_TYPEID_flowEndMilliseconds:
				case PSAMP_TYPEID_observationTimeSeconds:
					printLocaltime(type, pattern);
					return;
				case IPFIX_TYPEID_flowStartNanoseconds:
				case IPFIX_TYPEID_flowEndNanoseconds:
					hbnum = ntohll(*(uint64_t*)pattern);
					if (hbnum>0) {
						t = timentp64(*((ntp64*)(&hbnum)));
						fprintf(fh, "%u.%06d seconds", (int32_t)t.tv_sec, (int32_t)t.tv_usec);
					} else {
						fprintf(fh, "no value (only zeroes in field)");
					}
					return;
			}
			break;

		default:
		{
			if (type==InformationElement::IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont) ||
				type==InformationElement::IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont|IPFIX_PEN_reverse)) {
				printFrontPayload(type, pattern);
				return;
			}
		}
	}

	printUint(type, pattern);
}


void PrintHelpers::printFrontPayload(InformationElement::IeInfo type, IpfixRecord::Data* data)
{
	fprintf(fh, "'");
	for (uint32_t i=0; i<type.length; i++) {
		char c = data[i];
		if (isprint(c)) fprintf(fh, "%c", c);
		else fprintf(fh, ".");
	}
	fprintf(fh, "'");
}


/**
 * Creates a new IpfixPrinter. Do not forget to call @c startIpfixPrinter() to begin printing
 * @return handle to use when calling @c destroyIpfixPrinter()
 */
IpfixPrinter::IpfixPrinter(OutputType outputtype, string filename)
	: linesPrinted(0), outputType(outputtype), filename(filename)
{
	lastTemplate = 0;

	msg(MSG_INFO, "IpfixPrinter started with following parameters:");
	string type;
	switch (outputtype) {
		case TREE: type = "tree"; break;
		case LINE: type = "line"; break;
		case TABLE: type = "table"; break;
		case NONE: type = "no output"; break;
	}
	msg(MSG_INFO, "  - outputType=%s", type.c_str());
	string file = "standard output";
	if (filename!="") file = "in file '" + filename + "'";
	msg(MSG_INFO, "  - output=%s", file.c_str());

	fh = stdout;
	if (filename != "") {
		fh = fopen(filename.c_str(), "w");
		if (!fh)
			THROWEXCEPTION("IpfixPrinter: error opening file '%s': %s (%u)", filename.c_str(), strerror(errno), errno);
	}

	if (outputtype==TABLE)
		fprintf(fh, "srcipv4\tdstipv4\tsrcport\tdstport\tprot\tsrcpkts\tdstpkts\tsrcoct\tdstoct\tsrcstart\tsrcend\tdststart\tdstend\tsrcplen\tdstplen\tforcedexp\trevstart\tflowcnt\ttranoct\trevtranoct\n");
}

/**
 * Frees memory used by an IpfixPrinter
 */
IpfixPrinter::~IpfixPrinter()
{
	if (filename != "") {
		int ret = fclose(fh);
		if (ret)
			THROWEXCEPTION("IpfixPrinter: error closing file '%s': %s (%u)", filename.c_str(), strerror(errno), errno);
	}
}


/**
 * Prints a Template
 * @param sourceID SourceID of the exporting process
 * @param templateInfo Pointer to a structure defining the Template used
 */
void IpfixPrinter::onTemplate(IpfixTemplateRecord* record)
{
	boost::shared_ptr<TemplateInfo> templateInfo;
	switch (outputType) {
		case LINE:
			break;
		case TREE:
			templateInfo = record->templateInfo;
			switch(templateInfo->setId) {
				case TemplateInfo::NetflowTemplate:
					fprintf(fh, "\n-+--- Netflow Template (id=%u, uniqueId=%u) from ", templateInfo->templateId, templateInfo->getUniqueId());
					break;
				case TemplateInfo::NetflowOptionsTemplate:
					fprintf(fh, "\n-+--- Netflow Options Template (id=%u, uniqueId=%u) from ", templateInfo->templateId, templateInfo->getUniqueId());
					break;
				case TemplateInfo::IpfixTemplate:
					fprintf(fh, "\n-+--- Ipfix Template (id=%u, uniqueId=%u) from ", templateInfo->templateId, templateInfo->getUniqueId());
					break;
				case TemplateInfo::IpfixOptionsTemplate:
					fprintf(fh, "\n-+--- Ipfix Options Template (id=%u, uniqueId=%u) from ", templateInfo->templateId, templateInfo->getUniqueId());
					break;
				default:
					msg(MSG_ERROR, "IpfixPrinter: Template with unknown setId=%u, uniqueId=%u", templateInfo->setId, templateInfo->getUniqueId());

			}
			if (record->sourceID) {
				if (record->sourceID->exporterAddress.len == 4)
					printIPv4(*(uint32_t*)(&record->sourceID->exporterAddress.ip[0]));
				else
					fprintf(fh, "non-IPv4 address");
				fprintf(fh, ":%u (", record->sourceID->exporterPort);
				printProtocol(record->sourceID->protocol);
				fprintf(fh, ")\n");
			} else {
				fprintf(fh, "no sourceID given in template");
			}


			if (templateInfo->setId == TemplateInfo::IpfixTemplate) {
				for (int i = 0; i < templateInfo->fieldCount; i++) {
					TemplateInfo::FieldInfo* fi = &templateInfo->fieldInfo[i];
			                fprintf(fh, " '   `- %s\n", fi->type.toString().c_str());

				}
			}

			fprintf(fh, " `---\n\n");
			break;

		case TABLE:
		case NONE:
			break;
	}
	record->removeReference();
}

/**
 * Prints a Template that was announced to be destroyed
 * @param sourceID SourceID of the exporting process
 * @param dataTemplateInfo Pointer to a structure defining the DataTemplate used
 */
void IpfixPrinter::onTemplateDestruction(IpfixTemplateDestructionRecord* record)
{
	boost::shared_ptr<TemplateInfo> templateInfo = record->templateInfo;
	switch(templateInfo->setId) {
		case TemplateInfo::NetflowTemplate:
			fprintf(fh, "\n-+--- Destroyed Netflow Template (id=%u, uniqueId=%u) from ", templateInfo->templateId, templateInfo->getUniqueId());
			break;
		case TemplateInfo::NetflowOptionsTemplate:
			fprintf(fh, "\n-+--- Destroyed Netflow Options Template (id=%u, uniqueId=%u) from ", templateInfo->templateId, templateInfo->getUniqueId());
			break;
		case TemplateInfo::IpfixTemplate:
			fprintf(fh, "\n-+--- Destroyed Ipfix Template (id=%u, uniqueId=%u) from ", templateInfo->templateId, templateInfo->getUniqueId());
			break;
		case TemplateInfo::IpfixOptionsTemplate:
			fprintf(fh, "\n-+--- Destroyed Ipfix Options Template (id=%u, uniqueId=%u) from ", templateInfo->templateId, templateInfo->getUniqueId());
			break;
		default:
			msg(MSG_ERROR, "IpfixPrinter: Template destruction recordwith unknown setId=%u, uniqueId=%u", templateInfo->setId, templateInfo->getUniqueId());

	}
	if (record->sourceID) {
		if (record->sourceID->exporterAddress.len == 4)
			printIPv4(*(uint32_t*)(&record->sourceID->exporterAddress.ip[0]));
		else
			fprintf(fh, "non-IPv4 address");
		fprintf(fh, ":%u (", record->sourceID->exporterPort);
		printProtocol(record->sourceID->protocol);
		fprintf(fh, ")\n");
	} else {
		fprintf(fh, "no sourceID given in template");
	}
	record->removeReference();
}



/**
 * prints a datarecord in a special, easy-to-read data format in one line
 */
void IpfixPrinter::printOneLineRecord(IpfixDataRecord* record)
{
	boost::shared_ptr<TemplateInfo> dataTemplateInfo = record->templateInfo;
		char buf[100];

		if (linesPrinted == 0 || linesPrinted > 50) {
			fprintf(fh, "\n%11s %8s %14s %15s %24s %19s %12s %12s %12s %6s\n", "Flow recvd.", "Prot", "Source MAC", "Dest MAC", "Source IP:Port", "Dst IP:Port", "Pckts", "Bytes", "In VRFID", "Out VRFID");
			fprintf(fh, "----------------------------------------------------------------------------------------------------------------------------------------\n");
			linesPrinted = linesPrinted + 1;
		}
		struct tm* tm;
		//struct timeval tv;
/*		gettimeofday(&tv, 0);
		tm = localtime(reinterpret_cast<time_t*>(&tv.tv_sec));
		strftime(buf, ARRAY_SIZE(buf), "%T", tm);
		snprintf(buf2, ARRAY_SIZE(buf2), "%s.%03ld", buf, tv.tv_usec/1000);
		fprintf(fh, "%12s ", buf2);*/

		uint32_t timetype = 0;
		uint32_t starttime = 0;
		TemplateInfo::FieldInfo* fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_flowStartSeconds, 0);
		if (fi != NULL) {
			timetype = IPFIX_TYPEID_flowStartSeconds;
			time_t t = ntohl(*reinterpret_cast<time_t*>(record->data+fi->offset));
			starttime = t;
			tm = localtime(&t);
			//strftime(buf, 50, "%T", tm);
		} else {
			fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_flowStartMilliseconds, 0);
			if (fi != NULL) {
				timetype = IPFIX_TYPEID_flowStartMilliseconds;
				uint64_t t2 = ntohll(*reinterpret_cast<uint64_t*>(record->data+fi->offset));
				time_t t = t2/1000;
				starttime = t;
				tm = localtime(&t);
				strftime(buf, 50, "\n%T", tm);
			}/* else {
				fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_flowStartSysUpTime, 0);
				if (fi != NULL) {
					timetype = IPFIX_TYPEID_flowStartSysUpTime;
					starttime = ntohl(*reinterpret_cast<uint32_t*>(record->data+fi->offset));
					snprintf(buf, 50, "%u:%02u.%04u", starttime/60000, (starttime%60000)/1000, starttime%1000);
				} else {
					fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_flowStartSeconds, 0);
					if (fi != NULL) {
						timetype = IPFIX_TYPEID_flowStartNanoseconds;
						uint64_t t2 = ntohll(*reinterpret_cast<uint64_t*>(record->data+fi->offset));
						timeval t = timentp64(*((ntp64*)(&t2)));
						tm = localtime(&t.tv_sec);
						strftime(buf, 50, "%T", tm);
						starttime = t.tv_sec;
					}
				}
			}*/
		}
		if (timetype != 0) {
			fprintf(fh, "%7s ", buf);
			memset(buf, 0, ARRAY_SIZE(buf));
			uint32_t dur = 0;
			switch (timetype) {
				case IPFIX_TYPEID_flowStartSeconds:
					fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_flowEndSeconds, 0);
					if (fi != NULL) {
						dur = ntohl(*reinterpret_cast<uint32_t*>(record->data+fi->offset)) - starttime;
						dur *= 1000;
					}
					break;
				case IPFIX_TYPEID_flowStartMilliseconds:
					fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_flowEndMilliseconds, 0);
					if (fi != NULL) {
						//dur = ntohll(*reinterpret_cast<uint64_t*>(record->data+fi->offset)) - starttime;
						//dur *= 1000;
						uint64_t t2 = ntohll(*reinterpret_cast<uint64_t*>(record->data+fi->offset));
						time_t t = t2/1000;
						tm = localtime(&t);
						strftime(buf, 50, "%T", tm);
					}
					break;
				case IPFIX_TYPEID_flowStartSysUpTime:
					fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_flowEndSysUpTime, 0);
					if (fi != NULL) {
						dur = ntohl(*reinterpret_cast<uint32_t*>(record->data+fi->offset)) - starttime;
						dur *= 1000;
					}
					break;
				case IPFIX_TYPEID_flowStartNanoseconds:
					fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_flowEndNanoseconds, 0);
					if (fi != NULL) {
						uint64_t t2 = ntohll(*reinterpret_cast<uint64_t*>(record->data+fi->offset));
						timeval t = timentp64(*((ntp64*)(&t2)));
						dur = t.tv_sec*1000+t.tv_usec/1000 - starttime;
					}
			}
			//snprintf(buf, 50, "%u.%04u", (dur)/1000, dur%1000);
			fprintf(fh, "%7s ", buf);
		}
		else {
			fprintf(fh, "%20s %8s ", "---", "---");
		}

		fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_protocolIdentifier, 0);
		if (fi != NULL && fi->type.length==1) {
			snprintf(buf, ARRAY_SIZE(buf), "%hhu", *reinterpret_cast<uint8_t*>(record->data+fi->offset));
		} else {
			snprintf(buf, ARRAY_SIZE(buf), "---");
		}
		fprintf(fh, "%3s ", buf);

		fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_sourceMacAddress, 0);
		if (fi != NULL) {
			snprintf(buf, ARRAY_SIZE(buf), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			*reinterpret_cast<unsigned char*>(record->data),
			*reinterpret_cast<unsigned char*>(record->data + 1),
			*reinterpret_cast<unsigned char*>(record->data + 2),
			*reinterpret_cast<unsigned char*>(record->data + 3),
			*reinterpret_cast<unsigned char*>(record->data + 4),
			*reinterpret_cast<unsigned char*>(record->data + 5)
			);
		}
		else {
			snprintf(buf, ARRAY_SIZE(buf), "---");
		}
		fprintf(fh, "%17s", buf);

		fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_destinationMacAddress, 0);
		if (fi != NULL) {
			snprintf(buf, ARRAY_SIZE(buf), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			*reinterpret_cast<unsigned char*>(record->data + 6),
			*reinterpret_cast<unsigned char*>(record->data + 7),
			*reinterpret_cast<unsigned char*>(record->data + 8),
			*reinterpret_cast<unsigned char*>(record->data + 9),
			*reinterpret_cast<unsigned char*>(record->data + 10),
			*reinterpret_cast<unsigned char*>(record->data + 11)
			);
		}
		else {
			snprintf(buf, ARRAY_SIZE(buf), "%s", "---");
		}
		fprintf(fh, "%18s", buf);

		//print source ip v4 address
		fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_sourceIPv4Address, 0);
		uint32_t srcipv4 = 0;
		if (fi != NULL && fi->type.length>=4) {
			srcipv4 = *reinterpret_cast<uint32_t*>(record->data+fi->offset);
		}
		snprintf(buf, ARRAY_SIZE(buf), "%d.%d.%d.%d", (uint8_t)((srcipv4>>0)&0xFF), (uint8_t)((srcipv4>>8)&0xFF), (uint8_t)((srcipv4>>16)&0xFF), (uint8_t)((srcipv4>>24)&0xFF));
		fprintf(fh, "%16s ", buf);

		//print source ip v6 address
		fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_sourceIPv6Address, 0);
		uint16_t srcipv6_0 = 0;
		uint16_t srcipv6_1 = 0;
		uint16_t srcipv6_2 = 0;
		uint16_t srcipv6_3 = 0;
		uint16_t srcipv6_4 = 0;
		uint16_t srcipv6_5 = 0;
		uint16_t srcipv6_6 = 0;
		uint16_t srcipv6_7 = 0;
		if (fi != NULL && fi->type.length>=4) {
			srcipv6_0 = *reinterpret_cast<uint16_t*>(record->data+fi->offset);
			srcipv6_1 = *reinterpret_cast<uint16_t*>(record->data+fi->offset + 2);
			srcipv6_2 = *reinterpret_cast<uint16_t*>(record->data+fi->offset + 4);
			srcipv6_3 = *reinterpret_cast<uint16_t*>(record->data+fi->offset + 6);
			srcipv6_4 = *reinterpret_cast<uint16_t*>(record->data+fi->offset + 8);
			srcipv6_5 = *reinterpret_cast<uint16_t*>(record->data+fi->offset + 10);
			srcipv6_6 = *reinterpret_cast<uint16_t*>(record->data+fi->offset + 12);
			srcipv6_7 = *reinterpret_cast<uint16_t*>(record->data+fi->offset + 14);
		}
		reverse(&srcipv6_0);
		reverse(&srcipv6_1);
		reverse(&srcipv6_2);
		reverse(&srcipv6_3);
		reverse(&srcipv6_4);
		reverse(&srcipv6_5);
		reverse(&srcipv6_6);
		reverse(&srcipv6_7);
//		snprintf(buf, ARRAY_SIZE(buf), "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", srcipv6_0, srcipv6_1, srcipv6_2, srcipv6_3, srcipv6_4, srcipv6_5, srcipv6_6, srcipv6_7);
//		fprintf(fh, "%26s ", buf);

		//print src transport port
		fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_sourceTransportPort, 0);
		uint16_t srcport = 0;
		if (fi != NULL && fi->type.length==2) {
			srcport = ntohs(*reinterpret_cast<uint16_t*>(record->data+fi->offset));
		}
		snprintf(buf, ARRAY_SIZE(buf), "%" PRIu16, srcport);
		fprintf(fh, "%5s ", buf);

		//print dest ip v4 address
		fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_destinationIPv4Address, 0);
		uint32_t dstipv4 = 0;
		if (fi != NULL && fi->type.length>=4) {
			dstipv4 = *reinterpret_cast<uint32_t*>(record->data+fi->offset);
		}
		snprintf(buf, ARRAY_SIZE(buf), "%d.%d.%d.%d", (uint8_t)((dstipv4>>0)&0xFF), (uint8_t)((dstipv4>>8)&0xFF), (uint8_t)((dstipv4>>16)&0xFF), (uint8_t)((dstipv4>>24)&0xFF));
		fprintf(fh, "%15s ", buf);

		//print dest ip v6 address
		fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_destinationIPv6Address, 0);
		uint16_t dstipv6_0 = 0;
		uint16_t dstipv6_1 = 0;
		uint16_t dstipv6_2 = 0;
		uint16_t dstipv6_3 = 0;
		uint16_t dstipv6_4 = 0;
		uint16_t dstipv6_5 = 0;
		uint16_t dstipv6_6 = 0;
		uint16_t dstipv6_7 = 0;
		if (fi != NULL && fi->type.length>=4) {
			dstipv6_0 = *reinterpret_cast<uint16_t*>(record->data+fi->offset);
			dstipv6_1 = *reinterpret_cast<uint16_t*>(record->data+fi->offset + 2);
			dstipv6_2 = *reinterpret_cast<uint16_t*>(record->data+fi->offset + 4);
			dstipv6_3 = *reinterpret_cast<uint16_t*>(record->data+fi->offset + 6);
			dstipv6_4 = *reinterpret_cast<uint16_t*>(record->data+fi->offset + 8);
			dstipv6_5 = *reinterpret_cast<uint16_t*>(record->data+fi->offset + 10);
			dstipv6_6 = *reinterpret_cast<uint16_t*>(record->data+fi->offset + 12);
			dstipv6_7 = *reinterpret_cast<uint16_t*>(record->data+fi->offset + 14);
		}
		reverse(&dstipv6_0);
		reverse(&dstipv6_1);
		reverse(&dstipv6_2);
		reverse(&dstipv6_3);
		reverse(&dstipv6_4);
		reverse(&dstipv6_5);
		reverse(&dstipv6_6);
		reverse(&dstipv6_7);
//		snprintf(buf, ARRAY_SIZE(buf), "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", dstipv6_0, dstipv6_1, dstipv6_2, dstipv6_3, dstipv6_4, dstipv6_5, dstipv6_6, dstipv6_7);
//		fprintf(fh, "%26s ", buf);

		//print destination transport port
		fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_destinationTransportPort, 0);
		uint16_t dstport = 0;
		if (fi != NULL && fi->type.length==2) {
			dstport = ntohs(*reinterpret_cast<uint16_t*>(record->data+fi->offset));
		}
		snprintf(buf, ARRAY_SIZE(buf), "%" PRIu16, dstport);
		fprintf(fh, "%5s ", buf);

		//print packet count
		fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_packetDeltaCount, 0);
		if (fi != NULL) {
			printUint(buf, fi->type, record->data+fi->offset);
		} else {
			snprintf(buf, ARRAY_SIZE(buf), "---");
		}
		fprintf(fh, "%6s ", buf);

		//print octet count
		fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_octetDeltaCount, 0);
		if (fi != NULL) {
			printUint(buf, fi->type, record->data+fi->offset);
		} else {
			snprintf(buf, ARRAY_SIZE(buf), "---");
		}
		fprintf(fh, "%12s", buf);

		//print VRFID ingress field
		fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_ingressVRFID, 0);
		if (fi != NULL) {
			printUint(buf, fi->type, record->data+fi->offset);
		} else {
			snprintf(buf, ARRAY_SIZE(buf), "---");
		}
		fprintf(fh, "%12s", buf);


		//print VRFID egress field
		fi = dataTemplateInfo->getFieldInfo(IPFIX_TYPEID_egressVRFID, 0);
		if (fi != NULL) {
			printUint(buf, fi->type, record->data+fi->offset);
		} else {
			snprintf(buf, ARRAY_SIZE(buf), "---");
		}
		fprintf(fh, "%12s", buf);




		fflush(fh);
		memset(buf, 0, ARRAY_SIZE(buf));
		usleep(2500);
}

/**
 * prints record as a tree
 */
void IpfixPrinter::printTreeRecord(IpfixDataRecord* record)
{
	int i;

	switch(record->templateInfo->setId) {
		case TemplateInfo::NetflowTemplate:
			fprintf(fh, "\n-+--- Netflow Data Record (id=%u) from ", record->templateInfo->templateId);
			break;
		case TemplateInfo::NetflowOptionsTemplate:
			fprintf(fh, "\n-+--- Netflow Options Data Record (id=%u) from ", record->templateInfo->templateId);
			break;
		case TemplateInfo::IpfixTemplate:
			fprintf(fh, "\n-+--- Ipfix Data Record (id=%u) from ", record->templateInfo->templateId);
			break;
		case TemplateInfo::IpfixOptionsTemplate:
			fprintf(fh, "\n-+--- Ipfix Options Data Record (id=%u) from ", record->templateInfo->templateId);
			break;
		default:
			msg(MSG_ERROR, "IpfixPrinter: Template with unknown setid=%u", record->templateInfo->setId);

	}
	if (record->sourceID) {
		if (record->sourceID->exporterAddress.len == 4)
			printIPv4(*(uint32_t*)(&record->sourceID->exporterAddress.ip[0]));
		else
			fprintf(fh, "non-IPv4 address");
		fprintf(fh, ":%u (", record->sourceID->exporterPort);
		printProtocol(record->sourceID->protocol);
		fprintf(fh, ")\n");
	} else {
		fprintf(fh, "no sourceID given");
	}

	if(record->templateInfo->setId == TemplateInfo::IpfixOptionsTemplate) {
		fprintf(fh, " `- variable scope data\n");
		for(i = 0; i < record->templateInfo->scopeCount; i++) {
			fprintf(fh, " '   `- ");
			printFieldData(record->templateInfo->scopeInfo[i].type, (record->data + record->templateInfo->scopeInfo[i].offset));
			fprintf(fh, "\n");
		}
	}
	fprintf(fh, " `- variable data\n");
	for (i = 0; i < record->templateInfo->fieldCount; i++) {
		fprintf(fh, " '   `- ");
		printFieldData(record->templateInfo->fieldInfo[i].type, (record->data + record->templateInfo->fieldInfo[i].offset));
		fprintf(fh, "\n");
	}
	fprintf(fh, " `---\n\n");
}

/**
 * prints tab-seperated data from flows, these may be specified in configuration (TODO!)
 */
void IpfixPrinter::printTableRecord(IpfixDataRecord* record)
{
	Connection c(record);

	//fprintf(fh, "%llu\t%llu\t%u\t%u\t%llu\n", ntohll(c.srcOctets), ntohll(c.srcPackets), c.srcPayloadLen, c.srcPayloadPktCount, c.srcTimeEnd-c.srcTimeStart);
	fprintf(fh, "%s\t%s\t%hu\t%hu\t%hhu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%u\t%u\t%hhu\t%hhu\t%u\t%llu\t%llu\n",
			IPToString(c.srcIP).c_str(), IPToString(c.dstIP).c_str(), ntohs(c.srcPort), ntohs(c.dstPort), c.protocol,
			(long long unsigned)ntohll(c.srcPackets), (long long unsigned)ntohll(c.dstPackets), (long long unsigned)ntohll(c.srcOctets), (long long unsigned)ntohll(c.dstOctets),
			(long long unsigned)c.srcTimeStart, (long long unsigned)c.srcTimeEnd, (long long unsigned)c.dstTimeStart, (long long unsigned)c.dstTimeEnd,
			c.srcPayloadLen, c.dstPayloadLen, c.dpaForcedExport, c.dpaReverseStart, c.dpaFlowCount, (long long unsigned)c.srcTransOctets, (long long unsigned)c.dstTransOctets);

}

/**
 * Prints a DataRecord
 * @param sourceID SourceID of the exporting process
 * @param dataTemplateInfo Pointer to a structure defining the DataTemplate used
 * @param length Length of the data block supplied
 * @param data Pointer to a data block containing all variable fields
 */
void IpfixPrinter::onDataRecord(IpfixDataRecord* record)
{
	switch (outputType) {
		case LINE:
			printOneLineRecord(record);
			break;
		case TREE:
			printTreeRecord(record);
			break;

		case TABLE:
			printTableRecord(record);
			break;
		case NONE:
			break;
	}

	record->removeReference();
}
