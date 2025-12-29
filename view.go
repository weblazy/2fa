package main

import (
	"encoding/base32"
	"fmt"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/cmd/fyne_demo/data"
	"fyne.io/fyne/v2/cmd/fyne_demo/tutorials"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/urfave/cli/v2"
	"github.com/weblazy/crypto/aes"
	"github.com/weblazy/crypto/mode"
	"github.com/weblazy/easy/csvx"
)

var (
	// Tutorials defines the metadata for each tutorial
	Tutorials = map[string]tutorials.Tutorial{
		"2fa": {
			"2FA",
			"Gathering input widgets for data submission.",
			make2faTab,
		},
		"form": {
			"Form",
			"Gathering input widgets for data submission.",
			makeFormTab,
		},
	}

	// TutorialIndex  defines how our tutorials should be laid out in the index tree
	TutorialIndex = map[string][]string{
		"": {"form", "2fa"},
	}
)

func View(c *cli.Context) error {
	a := app.NewWithID("io.fyne.demo")
	a.SetIcon(data.FyneLogo)
	w := a.NewWindow("Fyne Demo")
	topWindow = w

	w.SetMaster()

	content := container.NewStack()
	title := widget.NewLabel("Component name")
	intro := widget.NewLabel("An introduction would probably go\nhere, as well as a")
	intro.Wrapping = fyne.TextWrapWord

	top := container.NewVBox(title, widget.NewSeparator(), intro)
	setTutorial := func(t tutorials.Tutorial) {
		if fyne.CurrentDevice().IsMobile() {
			child := a.NewWindow(t.Title)
			topWindow = child
			child.SetContent(t.View(topWindow))
			child.Show()
			child.SetOnClosed(func() {
				topWindow = w
			})
			return
		}

		title.SetText(t.Title)
		isMarkdown := len(t.Intro) == 0
		if !isMarkdown {
			intro.SetText(t.Intro)
		}

		if t.Title == "Welcome" || isMarkdown {
			top.Hide()
		} else {
			top.Show()
		}

		content.Objects = []fyne.CanvasObject{t.View(w)}
		content.Refresh()
	}

	tutorial := container.NewBorder(
		top, nil, nil, nil, content)
	if fyne.CurrentDevice().IsMobile() {
		w.SetContent(makeNav(setTutorial, false))
	} else {
		split := container.NewHSplit(makeNav(setTutorial, true), tutorial)
		split.Offset = 0.2
		w.SetContent(split)
	}
	w.Resize(fyne.NewSize(640, 460))
	w.ShowAndRun()
	return nil
}

func make2faTab(_ fyne.Window) fyne.CanvasObject {
	text, _ := Gen2FAText()
	return container.NewVBox(
		&widget.Label{
			Text:       text,
			Selectable: true,
		},
	)
}

func Gen2FAText() (string, error) {
	csv, err := csvx.NewCSV(file, ',', "\n")
	if err != nil {
		return "", err
	}
	defer func() {
		_ = csv.Close()
	}()
	text := ""
	epochSeconds := time.Now().Unix()
	secondsRemaining := 30 - (epochSeconds % 30)

	for row, err := csv.ReadLine(); err == nil; row, err = csv.ReadLine() {
		if len(row) < 2 {
			continue
		}
		if row[0] == "password" {
			break
		}
		input := row[1]
		// decode the key from the first argument
		inputNoSpaces := strings.Replace(input, " ", "", -1)
		inputNoSpacesUpper := strings.ToUpper(inputNoSpaces)
		key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(inputNoSpacesUpper)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}

		// generate a one-time password using the time at 30-second intervals

		pwd := oneTimePassword(key, toBytes(epochSeconds/30))

		text += fmt.Sprintf("%s: %06d %d秒后过期\n", row[0], pwd, secondsRemaining)
	}
	return text, nil
}

func GenPasswordText() (string, error) {
	csv, err := csvx.NewCSV(file, ',', "\n")
	if err != nil {
		return "", err
	}
	defer func() {
		_ = csv.Close()
	}()
	key := c.String("key")
	isPassword := false
	text := ""
	for row, err := csv.ReadLine(); err == nil; row, err = csv.ReadLine() {
		if len(row) < 2 {
			continue
		}
		if row[0] == "password" {
			isPassword = true
			continue
		}

		if !isPassword || (key != row[0] && key != "all") {
			continue
		}
		res, _ := aes.NewAes([]byte(aesKey)).WithMode(&mode.ECBMode{}).Decrypt(row[1])
		text += fmt.Sprintf("%s: %s\n", row[0], res)
	}
	return text, nil
}

func makeNav(setTutorial func(tutorial tutorials.Tutorial), loadPrevious bool) fyne.CanvasObject {
	a := fyne.CurrentApp()

	tree := &widget.Tree{
		ChildUIDs: func(uid string) []string {
			return TutorialIndex[uid]
		},
		IsBranch: func(uid string) bool {
			children, ok := TutorialIndex[uid]

			return ok && len(children) > 0
		},
		CreateNode: func(branch bool) fyne.CanvasObject {
			return widget.NewLabel("Collection Widgets")
		},
		UpdateNode: func(uid string, branch bool, obj fyne.CanvasObject) {
			t, ok := Tutorials[uid]
			if !ok {
				fyne.LogError("Missing tutorial panel: "+uid, nil)
				return
			}
			obj.(*widget.Label).SetText(t.Title)
		},
		OnSelected: func(uid string) {
			if t, ok := Tutorials[uid]; ok {
				for _, f := range tutorials.OnChangeFuncs {
					f()
				}
				tutorials.OnChangeFuncs = nil // Loading a page registers a new cleanup.

				a.Preferences().SetString(preferenceCurrentTutorial, uid)
				setTutorial(t)
			}
		},
	}

	if loadPrevious {
		currentPref := a.Preferences().StringWithFallback(preferenceCurrentTutorial, "welcome")
		tree.Select(currentPref)
	}

	themes := container.NewGridWithColumns(2,
		widget.NewButton("Dark", func() {
		}),
		widget.NewButton("Light", func() {
		}),
	)

	return container.NewBorder(nil, themes, nil, nil, tree)
}

func twofaView(topTitle, text string) {
	a := app.New()
	w := a.NewWindow(topTitle)

	hello := &widget.Label{
		Text:       text,
		Selectable: true,
	}
	w.SetContent(container.NewVBox(
		hello,
	))

	w.Resize(fyne.NewSize(640, 460))
	w.ShowAndRun()

}

func passwordView(topTitle string) {
	a := app.New()
	w := a.NewWindow(topTitle)

	w.SetContent(container.NewVBox(
		makeFormTab(w),
	))

	w.Resize(fyne.NewSize(640, 460))
	w.ShowAndRun()

}

func makeFormTab(_ fyne.Window) fyne.CanvasObject {
	name := widget.NewEntry()
	name.SetPlaceHolder("John Smith")

	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Password")

	hello := &widget.Label{
		Text:       "",
		Selectable: true,
	}
	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "key", Widget: name, HintText: ""},
			{Text: "password", Widget: password, HintText: ""},
		},
		OnCancel: func() {
			name.SetText("")
			password.SetText("")
		},
		OnSubmit: func() {
			fmt.Println(name.Text)
			fmt.Println(password.Text)
			fyne.CurrentApp().SendNotification(&fyne.Notification{
				Title:   "Form for: " + name.Text,
				Content: name.Text,
			})
			res, _ := aes.NewAes([]byte(aesKey)).WithMode(&mode.ECBMode{}).Encrypt(password.Text)
			hello.SetText(res)
		},
	}
	form.Append("密文", hello)
	return form
}
