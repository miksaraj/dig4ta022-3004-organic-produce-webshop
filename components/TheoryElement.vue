<template>
	<div>
		<h3>{{ item.header }}</h3>
		<div v-for="section in item.text" :key="section.type">
			<p v-if="section.type == 'p'">{{ section.content }}</p>
			<ul v-else-if="section.type == 'ul'">
				<li v-for="listItem in section.content" :key="listItem">
					{{ listItem }}
				</li>
			</ul>
			<b-img-lazy
				v-else-if="section.type == 'img'"
				:src="section.content"
				fluid
				:alt="section.alt"
			/>
		</div>
		<br />
		<b-form-checkbox v-model="done" size="lg" class="done-box">
			Luettu!
		</b-form-checkbox>
	</div>
</template>

<style scoped>
.done-box {
	float: right;
}

.done-box .custom-control-label::before {
	border-style: dotted !important;
}

.done-box.custom-control.custom-checkbox.b-custom-control-lg {
	font-size: smaller !important;
	opacity: 50% !important;
}
</style>

<script>
import { mapGetters } from 'vuex'
export default {
	name: 'TheoryElement',
	computed: {
		...mapGetters({
			contentById: 'content/contentById',
			isRead: 'progress/isRead'
		}),
		item() {
			return this.contentById(this.id)
		},
		id() {
			return this.$attrs.id
		},
		done: {
			get() {
				return this.isRead(this.id)
			},
			set() {
				this.$store.dispatch('progress/toggleRead', this.id)
			}
		}
	}
}
</script>
