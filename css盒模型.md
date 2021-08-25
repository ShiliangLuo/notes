# css盒模型

`Box`是`css`布局的对象和基本单元，一个页面由很多个`Box`组成。元素的类型和`display`属性决定了这个`Box`的类型。

* block-level box: `display`属性为`block`、`list-item`、`table`的元素
* inline-level box: `display`属性为`inline`、`inline-block`、`inline-table`的元素

## 标准盒模型

`box-sizing`属性为`content-box`，盒子的`总宽高 = width/height + border + padding + margin`

## IE盒模型

`box-sizing`属性为`border-box`，盒子的`总宽高 = width/height + margin`
