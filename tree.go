package main

import (
	"bytes"
	"fmt"
	"github.com/Macmod/godap/utils"
	"github.com/gdamore/tcell/v2"
	"github.com/go-ldap/ldap/v3"
	"github.com/rivo/tview"
	"strconv"
	"strings"
)

var loadedDNs map[string]*ldap.Entry = make(map[string]*ldap.Entry)

func createTreeNodeFromEntry(entry *ldap.Entry) *tview.TreeNode {
	_, ok := loadedDNs[entry.DN]

	if !ok {
		nodeName := getNodeName(entry)

		node := tview.NewTreeNode(nodeName).
			SetReference(entry.DN).
			SetSelectable(true)

		uac := entry.GetAttributeValue("userAccountControl")
		uacNum, err := strconv.Atoi(uac)

		if err == nil && colors && uacNum&2 != 0 {
			node.SetColor(tcell.GetColor("red"))
		}

		loadedDNs[entry.DN] = entry
		return node
	} else {
		return nil
	}
}

// Unloads child nodes and their attributes from the cache
func unloadChildren(node *tview.TreeNode) {
	children := node.GetChildren()
	for _, child := range children {
		childDN := child.GetReference().(string)
		delete(loadedDNs, childDN)
		node.RemoveChild(child)
	}
}

// Loads child nodes and their attributes directly from LDAP
func loadChildren(node *tview.TreeNode) {
	baseDN := node.GetReference().(string)
	entries, err := queryLDAP(conn, baseDN, searchFilter, ldap.ScopeSingleLevel)
	if err != nil {
		return
	}

	attrsPanel.Clear()

	for _, entry := range entries {
		childNode := createTreeNodeFromEntry(entry)
		attributes := entry.Attributes

		row := 0
		for _, attribute := range attributes {
			attrsPanel.SetCell(row, 0,
				tview.NewTableCell(attribute.Name))

			col := 1
			for _, value := range attribute.Values {
				myCell := tview.NewTableCell(value)

				attrsPanel.SetCell(row, col, myCell)

				col = col + 1
			}

			row = row + 1
		}

		if childNode != nil {
			node.AddChild(childNode)
		}
	}
}

func reloadAttributesPanel(node *tview.TreeNode, useCache bool) error {
	ref := node.GetReference()
	if ref == nil {
		return fmt.Errorf("Couldn't reload attributes: no node selected")
	}

	var attributes []*ldap.EntryAttribute

	baseDN := ref.(string)

	if useCache {
		entry, ok := loadedDNs[baseDN]
		if ok {
			attributes = entry.Attributes
		} else {
			return fmt.Errorf("Couldn't reload attributes: node not cached")
		}
	} else {
		entries, err := queryLDAP(conn, baseDN, searchFilter, ldap.ScopeBaseObject)
		if err != nil {
			return err
		}

		if len(entries) != 1 {
			return fmt.Errorf("Entry not found")
		}

		entry := entries[0]
		loadedDNs[baseDN] = entry

		attributes = entry.Attributes
	}

	attrsPanel.Clear()

	row := 0
	for _, attribute := range attributes {
		var cellName string = attribute.Name

		var cellValues []string

		attrsPanel.SetCell(row, 0, tview.NewTableCell(cellName))

		if formatAttrs {
			cellValues = utils.FormatLDAPAttribute(attribute)
		} else {
			cellValues = attribute.Values
		}

		if !expandAttrs {
			myCell := tview.NewTableCell(strings.Join(cellValues, "; "))

			if colors {
				color, ok := utils.GetAttrCellColor(cellName, attribute.Values[0])
				if ok {
					myCell.SetTextColor(tcell.GetColor(color))
				}
			}

			attrsPanel.SetCell(row, 1, myCell)
			row = row + 1
			continue
		}

		for idx, cellValue := range cellValues {
			myCell := tview.NewTableCell(cellValue)

			if colors {
				var refValue string
				if !expandAttrs || len(cellValues) == 1 {
					refValue = attribute.Values[idx]
				} else {
					refValue = cellValue
				}

				color, ok := utils.GetAttrCellColor(cellName, refValue)

				if ok {
					myCell.SetTextColor(tcell.GetColor(color))
				}
			}

			if idx == 0 {
				attrsPanel.SetCell(row, 1, myCell)
			} else {
				if expandAttrs {
					if attrLimit == -1 || idx < attrLimit {
						attrsPanel.SetCell(row, 1, myCell)
						if idx == attrLimit-1 {
							attrsPanel.SetCell(row+1, 1, tview.NewTableCell("[entries hidden]"))
							row = row + 2
							break
						}
					}
				}
			}

			row = row + 1
		}
	}

	return nil
}

func getNodeName(entry *ldap.Entry) string {
	var classEmojisBuf bytes.Buffer
	var emojisPrefix string

	objectClasses := entry.GetAttributeValues("objectClass")
	for _, objectClass := range objectClasses {
		if emoji, ok := utils.EmojiMap[objectClass]; ok {
			classEmojisBuf.WriteString(emoji)
		}
	}

	emojisPrefix = classEmojisBuf.String()

	if len(emojisPrefix) == 0 {
		emojisPrefix = utils.EmojiMap["container"]
	}

	if emojis {
		return emojisPrefix + entry.GetAttributeValue("name")
	}

	return entry.GetAttributeValue("name")
}

func updateEmojis() {
	treePanel.GetRoot().Walk(func(node *tview.TreeNode, parent *tview.TreeNode) bool {
		ref := node.GetReference()
		if ref != nil {
			entry, ok := loadedDNs[ref.(string)]

			if ok {
				node.SetText(getNodeName(entry))
			}
		}

		return true
	})
}

func renderPartialTree(conn *ldap.Conn, rootDN string, searchFilter string) *tview.TreeNode {
	rootEntries, err := queryLDAP(conn, rootDN, searchFilter, ldap.ScopeSingleLevel)

	if err != nil {
		return nil
	}

	rootNode = tview.NewTreeNode(utils.EmojiMap["root"] + rootDN).
		SetReference(rootDN).
		SetSelectable(true)
	for _, entry := range rootEntries {
		node := createTreeNodeFromEntry(entry)
		if node != nil {
			rootNode.AddChild(node)
		}
	}

	return rootNode
}

func reloadPage() {
	attrsPanel.Clear()

	clear(loadedDNs)

	rootNode = renderPartialTree(conn, rootDN, searchFilter)
	treePanel.SetRoot(rootNode).SetCurrentNode(rootNode)
}
