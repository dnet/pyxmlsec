#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
#
# $Id$
#
# PyXMLSec - Python bindings for XML Security library (XMLSec)
#
# Copyright (C) 2003-2004 Valery Febvre
# http://pyxmlsec.labs.libre-entreprise.org
#
# Author: Valery Febvre <vfebvre@easter-eggs.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

from os import environ
if (not environ.has_key("DISPLAY")):
    raise ImportError, "DISPLAY environment variable not set"

import sys, string, commands

import pygtk
pygtk.require('2.0')

import gtk, gobject

PACKAGE = "pyxmlsec-demo"

ntb = tview_exec = tview_src = None

class Gadget:
    def connect_signals (self, cbs):
        for cb in cbs:
            self.connect (cb[0], cb[1])

class TreeViewColumn(gtk.TreeViewColumn):
    def __init__(self, data, id):
        if data[1] == gobject.TYPE_STRING or data[1] == gobject.TYPE_UINT:
            renderer = gtk.CellRendererText ()
            if len(data) >= 4:
                renderer.set_property ('editable', data[3])
            gtk.TreeViewColumn.__init__ (self, data[0], renderer, text=id)
            self.set_reorderable(gtk.TRUE)
        elif data[1] == gobject.TYPE_OBJECT:
            renderer = gtk.CellRendererPixbuf ()
            gtk.TreeViewColumn.__init__ (self, data[0], renderer, pixbuf=id)
        ## is col sortable ?
        if len(data) >= 3 and data[2]:
            self.set_sort_column_id (id)
        ## is col resizable ?
        if len(data) >= 5:
            self.set_resizable (data[4])
        ## set sizing type
        if len(data) >= 6:
            self.set_sizing (data[5])

class ListStore(gtk.ListStore):
    def __init__(self, types):
        self.types = types
        apply (gtk.ListStore.__init__, [self] + self.types)

class CList(gtk.TreeView, Gadget):
    def __init__(self, cols, cbs=[]):
        self.cols = cols
        self.model = ListStore (self.__get_cols_types ())
        gtk.TreeView.__init__ (self, self.model)
        self.nb_rows = 0
        i = 0
        for col in self.cols:
            column = TreeViewColumn (col, i)
            self.append_column (column)
            i = i + 1
        # set callbacks
        self.connect_signals (cbs)
        self.show ()
    def __get_cols_types(self):
        types = []
        for col in self.cols:
            types.append(col[1])
        return types
    def append_row (self, data):
        self.model.append (data)
        self.nb_rows += 1
    def clear (self):
        self.model.clear ()
        self.nb_rows = 0
    def get_row (self, row=None):
        if row is not None:
            model = self.model
            iter  = self.model.get_iter (row)
        else:
            ## only work in 'single' or 'browse' modes
            ## with 'multiple' mode, only use with 'row' attribut
            model, iter = self.get_selection ().get_selected ()
        values = []
        for i in range (0, len (self.cols)):
            values.append (model.get_value (iter, i))
        return values
    def get_selected_multiple(self):
        rows_selected = []
        selection = self.get_selection ()
        for i in range(0, self.nb_rows):
            if selection.iter_is_selected (self.model.get_iter (i)):
                rows_selected.append (i)
        return rows_selected

class TView(gtk.TextView):
    def __init__(self):
        gtk.TextView.__init__ (self)
        self.set_editable(gtk.FALSE)
        self.buffer = self.get_buffer()
        self.set_wrap_mode(gtk.WRAP_WORD)
        tag = gtk.TextTag('monospace')
        tag.set_property('family', 'monospace')
        self.buffer.get_tag_table().add(tag)
    def clear(self):
        start, end = self.get_buffer().get_bounds()
        self.buffer.delete(start, end)
    def append_text(self, text, nb_tab=0):
        if text == '': return
        iter = self.buffer.get_end_iter()
        if nb_tab:
            tab = '\n' + '    ' * nb_tab
            text = '    ' * nb_tab + string.replace(text, '\n', tab)
        self.buffer.insert_with_tags_by_name(iter, latin_to_utf8(text+'\n'), "monospace")
        # self.buffer.insert(iter, latin_to_utf8(text+'\n'))

def quit(widget=None, *args):
    gtk.mainquit()

def interface():
    global ntb, tview_exec, tview_src
    # window
    window = gtk.Window()
    window.set_wmclass(PACKAGE, PACKAGE)
    window.set_title(PACKAGE)
    window.resize(800, 600)
    window.set_resizable(gtk.TRUE)
    window.connect('destroy', quit)
    # HPaned
    vpaned = gtk.VPaned()
    window.add(vpaned)
    # ScrolledWindow for clist
    sw_clist = gtk.ScrolledWindow()
    sw_clist.set_policy (gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
    vpaned.pack1 (sw_clist, gtk.FALSE, gtk.FALSE)
    # CList to launch examples
    clist = CList(cols = [('Examples (double click for demo)', gobject.TYPE_STRING, 0, 0, 0, 0)],
                  cbs  = [('row-activated', on_clist_row_doubleclicked)])
    clist.get_selection().connect('changed', on_clist_row_clicked)
    clist.append_row(['Signing a template file'])
    clist.append_row(['Signing a file with a dynamicaly created template'])
    clist.append_row(['Signing a file with a dynamicaly created template and an X509 certificate'])
    clist.append_row(['Verifying a file using a single key'])
    clist.append_row(['Verifying a file using keys manager'])
    clist.append_row(['Verifying a file signed with X509 certificate'])
    clist.append_row(['Verifying a signature with additional restrictions'])
    clist.append_row(['Encrypting data using a template file'])
    clist.append_row(['Encrypting XML file with a dynamicaly created template'])
    clist.append_row(['Encrypting XML file with a session key and dynamicaly created template'])
    clist.append_row(['Decrypting an encrypted file using a single key'])
    clist.append_row(['Decrypting an encrypted file using keys manager'])
    sw_clist.add(clist)
    # Notebook
    ntb = gtk.Notebook()
    vpaned.pack2 (ntb, gtk.FALSE, gtk.FALSE)
    # ScrolledWindow for TextView Source
    sw_tview_src = gtk.ScrolledWindow()
    sw_tview_src.set_policy (gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
    ntb.append_page (sw_tview_src, gtk.Label("Source"))
    # TextView Source
    tview_src = TView()
    sw_tview_src.add(tview_src)
    # ScrolledWindow for TextView Execution
    sw_tview_exec = gtk.ScrolledWindow()
    sw_tview_exec.set_policy (gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
    ntb.append_page (sw_tview_exec, gtk.Label("Execution"))
    # TextView Execution
    tview_exec = TView()
    sw_tview_exec.add(tview_exec)
    # Show all widgets
    window.show_all()

def utf8_to_latin(s):
    return s.encode('iso-8859-1', 'replace')
def latin_to_utf8(s):
    return unicode(s, 'iso-8859-1')

def on_clist_row_clicked(selection):
    ntb.set_current_page(0)
    tview_src.clear()
    tview_exec.clear()
    model, iter = selection.get_selected()
    row = model.get_path(iter)[0]
    if row == 0:
        tview_src.append_text(commands.getoutput('cat ./sign1.py'))
    elif row == 1:
        tview_src.append_text(commands.getoutput('cat ./sign2.py'))
    elif row == 2:
        tview_src.append_text(commands.getoutput('cat ./sign3.py'))
    elif row == 3:
        tview_src.append_text(commands.getoutput('cat ./verify1.py'))
    elif row == 4:
        tview_src.append_text(commands.getoutput('cat ./verify2.py'))
    elif row == 5:
        tview_src.append_text(commands.getoutput('cat ./verify3.py'))
    elif row == 6:
        tview_src.append_text(commands.getoutput('cat ./verify4.py'))
    elif row == 7:
        tview_src.append_text(commands.getoutput('cat ./encrypt1.py'))
    elif row == 8:
        tview_src.append_text(commands.getoutput('cat ./encrypt2.py'))
    elif row == 9:
        tview_src.append_text(commands.getoutput('cat ./encrypt3.py'))
    elif row == 10:
        tview_src.append_text(commands.getoutput('cat ./decrypt1.py'))
    elif row == 11:
        tview_src.append_text(commands.getoutput('cat ./decrypt2.py'))

def on_clist_row_doubleclicked(treeview, path, treeviewcolumn):
    ntb.set_current_page(1)
    tview_exec.clear()
    row = path[0]
    if row == 0:
        tview_exec.append_text('Signing a template file')
        tview_exec.append_text('-----------------------')
        tview_exec.append_text('Template file sign1-tmpl.xml', 1)
        tview_exec.append_text('----------------------------', 1)
        tview_exec.append_text(commands.getoutput('cat ./sign1-tmpl.xml'), 2)
        tview_exec.append_text('Result', 1)
        tview_exec.append_text('------', 1)
        tview_exec.append_text(commands.getoutput('./sign1.py sign1-tmpl.xml rsakey.pem'), 2)
    elif row == 1:
        tview_exec.append_text('Signing a file with a dynamicaly created template')
        tview_exec.append_text('-------------------------------------------------')
        tview_exec.append_text('Doc file sign2-doc.xml', 1)
        tview_exec.append_text('----------------------', 1)
        tview_exec.append_text(commands.getoutput('cat ./sign2-doc.xml'), 2)
        tview_exec.append_text('Result', 1)
        tview_exec.append_text('------', 1)
        tview_exec.append_text(commands.getoutput('./sign2.py sign2-doc.xml rsakey.pem'), 2)
    elif row == 2:
        tview_exec.append_text('Signing a file with a dynamicaly created template and an X509 certificate')
        tview_exec.append_text('-------------------------------------------------------------------------')
        tview_exec.append_text('Doc file sign3-doc.xml', 1)
        tview_exec.append_text('----------------------', 1)
        tview_exec.append_text(commands.getoutput('cat ./sign3-doc.xml'), 2)
        tview_exec.append_text('Result', 1)
        tview_exec.append_text('------', 1)
        tview_exec.append_text(commands.getoutput('./sign3.py sign3-doc.xml rsakey.pem rsacert.pem'), 2)
    elif row == 3:
        tview_exec.append_text('Verifying a file using a single key')
        tview_exec.append_text('-----------------------------------')
        tview_exec.append_text('Doc file sign1-res.xml', 1)
        tview_exec.append_text('----------------------', 1)
        tview_exec.append_text(commands.getoutput('cat ./sign1-res.xml'), 2)
        tview_exec.append_text('Result', 1)
        tview_exec.append_text('------', 1)
        tview_exec.append_text(commands.getoutput('./verify1.py sign1-res.xml rsapub.pem'), 2)
    elif row == 4:
        tview_exec.append_text('Verifying a file using keys manager')
        tview_exec.append_text('-----------------------------------')
        tview_exec.append_text('Doc file sign2-res.xml', 1)
        tview_exec.append_text('----------------------', 1)
        tview_exec.append_text(commands.getoutput('cat ./sign2-res.xml'), 2)
        tview_exec.append_text('Result', 1)
        tview_exec.append_text('------', 1)
        tview_exec.append_text(commands.getoutput('./verify2.py sign2-res.xml rsapub.pem'), 2)
    elif row == 5:
        tview_exec.append_text('Verifying a file signed with X509 certificate')
        tview_exec.append_text('---------------------------------------------')
        tview_exec.append_text('Doc file sign3-res.xml', 1)
        tview_exec.append_text('----------------------', 1)
        tview_exec.append_text(commands.getoutput('cat ./sign3-res.xml'), 2)
        tview_exec.append_text('Result', 1)
        tview_exec.append_text('------', 1)
        tview_exec.append_text(commands.getoutput('./verify3.py sign3-res.xml rootcert.pem'), 2)
    elif row == 6:
        tview_exec.append_text('Verifying a signature with additional restrictions')
        tview_exec.append_text('--------------------------------------------------')
        tview_exec.append_text('Doc file verify4-res.xml', 1)
        tview_exec.append_text('------------------------', 1)
        tview_exec.append_text(commands.getoutput('cat ./verify4-res.xml'), 2)
        tview_exec.append_text('Result', 1)
        tview_exec.append_text('------', 1)
        tview_exec.append_text(commands.getoutput('./verify4.py verify4-res.xml rootcert.pem'), 2)
    elif row == 7:
        tview_exec.append_text('Encrypting data using a template file')
        tview_exec.append_text('-------------------------------------')
        tview_exec.append_text('Template file encrypt1-tmpl.xml', 1)
        tview_exec.append_text('-------------------------------', 1)
        tview_exec.append_text(commands.getoutput('cat ./encrypt1-tmpl.xml'), 2)
        tview_exec.append_text('Result', 1)
        tview_exec.append_text('------', 1)
        tview_exec.append_text(commands.getoutput('./encrypt1.py encrypt1-tmpl.xml deskey.bin'), 2)
    elif row == 8:
        tview_exec.append_text('Encrypting XML file with a dynamicaly created template')
        tview_exec.append_text('------------------------------------------------------')
        tview_exec.append_text('Doc file encrypt2-doc.xml', 1)
        tview_exec.append_text('-------------------------', 1)
        tview_exec.append_text(commands.getoutput('cat ./encrypt2-doc.xml'), 2)
        tview_exec.append_text('Result', 1)
        tview_exec.append_text('------', 1)
        tview_exec.append_text(commands.getoutput('./encrypt2.py encrypt2-doc.xml deskey.bin'), 2)
    elif row == 9:
        tview_exec.append_text('Encrypting XML file with a session key and dynamicaly created template')
        tview_exec.append_text('----------------------------------------------------------------------')
        tview_exec.append_text('Doc file encrypt3-doc.xml', 1)
        tview_exec.append_text('-------------------------', 1)
        tview_exec.append_text(commands.getoutput('cat ./encrypt3-doc.xml'), 2)
        tview_exec.append_text('Result', 1)
        tview_exec.append_text('------', 1)
        tview_exec.append_text(commands.getoutput('./encrypt3.py encrypt3-doc.xml rsakey.pem'), 2)
    elif row == 10:
        tview_exec.append_text('Decrypting an encrypted file using a single key')
        tview_exec.append_text('-----------------------------------------------')
        tview_exec.append_text('Doc file encrypt1-res.xml', 1)
        tview_exec.append_text('-------------------------', 1)
        tview_exec.append_text(commands.getoutput('cat ./encrypt1-res.xml'), 2)
        tview_exec.append_text('Result', 1)
        tview_exec.append_text('------', 1)
        tview_exec.append_text(commands.getoutput('./decrypt1.py encrypt1-res.xml deskey.bin'), 2)
    elif row == 11:
        tview_exec.append_text('Decrypting an encrypted file using keys manager')
        tview_exec.append_text('-----------------------------------------------')
        tview_exec.append_text('Doc file encrypt2-res.xml', 1)
        tview_exec.append_text('-------------------------', 1)
        tview_exec.append_text(commands.getoutput('cat ./encrypt2-res.xml'), 2)
        tview_exec.append_text('Result', 1)
        tview_exec.append_text('------', 1)
        tview_exec.append_text(commands.getoutput('./decrypt2.py encrypt2-res.xml deskey.bin'), 2)

if __name__ == '__main__':
    interface()
    gtk.main()
